/*
geoip-policyd
Copyright (C) 2021  Rößner-Network-Solutions

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/oschwald/maxminddb-golang"
	"github.com/segmentio/ksuid"
)

const (
	GET    = "GET"
	POST   = "POST"
	PUT    = "PUT"
	PATCH  = "PATCH"
	DELETE = "DELETE"
)

const (
	Sender       = "sender"
	Client       = "client"
	SASLUsername = "sasl_username"
)

// HTTPApp Basic auth for the HTTP service.
type HTTPApp struct {
	auth struct {
		username string
		password string
	}
	x509 struct {
		cert string
		key  string
	}
	useBasicAuth bool
	useSSL       bool
}

type Body struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

type RESTResult struct {
	GUID      string `json:"guid"`
	Object    string `json:"object"`
	Operation string `json:"operation"`
	Result    any    `json:"result"`
}

type HTTP struct {
	guid           string
	responseWriter http.ResponseWriter
	request        *http.Request
}

func HasContentType(request *http.Request, mimetype string) bool {
	contentType := request.Header.Get("Content-type")

	for _, v := range strings.Split(contentType, ",") {
		t, _, err := mime.ParseMediaType(v)
		if err != nil {
			break
		}

		if t == mimetype {
			return true
		}
	}

	return false
}

func (h *HTTP) LogInfo(message ...any) {
	var args = []any{
		"guid", h.guid,
		"client", h.request.RemoteAddr,
		"request", h.request.Method,
		"path", h.request.URL.Path,
	}

	args = append(args, message...)

	level.Info(logger).Log(args...)
}

func (h *HTTP) LogError(err error) {
	level.Error(logger).Log(
		"guid", h.guid,
		"client", h.request.RemoteAddr,
		"request", h.request.Method,
		"path", h.request.URL.Path,
		"error", err)
}

func (h *HTTP) GETReload() {
	var (
		err               error
		customSettings    *CustomSettings
		newCustomSettings *CustomSettings
	)

	geoip := &GeoIP{}
	geoip.Reader, err = maxminddb.Open(config.GeoipPath)

	if err != nil {
		h.responseWriter.WriteHeader(http.StatusInternalServerError)
		h.LogError(err)

		return
	}

	geoIPStore.Store(geoip)

	h.LogInfo("file", config.GeoipPath, "result", "reloaded")

	//nolint:forcetypeassert // Global variable
	if customSettings = customSettingsStore.Load().(*CustomSettings); customSettings != nil {
		newCustomSettings = initCustomSettings(config)
		if newCustomSettings != nil {
			customSettingsStore.Store(newCustomSettings)

			h.LogInfo("file", config.CustomSettingsPath, "result", "reloaded")
		}
	}

	h.responseWriter.WriteHeader(http.StatusAccepted)
}

func (h *HTTP) GETCustomSettings() {
	h.responseWriter.Header().Set("Content-Type", "application/json")

	//nolint:forcetypeassert // Global variable
	if customSettings := customSettingsStore.Load().(*CustomSettings); customSettings != nil {
		if err := json.NewEncoder(h.responseWriter).Encode(customSettings.Data); err != nil {
			h.LogError(err)

			return
		}
	} else {
		h.responseWriter.WriteHeader(http.StatusNoContent)
	}
}

func (h *HTTP) POSTRemove() {
	var requestData *Body

	if !HasContentType(h.request, "application/json") {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errWrongCT)

		return
	}

	body, err := io.ReadAll(h.request.Body)
	if err != nil {
		h.responseWriter.WriteHeader(http.StatusInternalServerError)
		h.LogError(err)

		return
	}

	requestData = &Body{}
	if err = json.Unmarshal(body, requestData); err != nil {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(err)

		return
	}

	if requestData.Key == Sender {
		sender, ok := requestData.Value.(string)
		if !ok {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errValueMustBeString)

			return
		}

		if sender == "" {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errValueMustNotBeEmpty)

			return
		}

		if config.UseLDAP {
			var (
				ldapReply   LdapReply
				ldapRequest LdapRequest
			)

			ldapReplyChan := make(chan LdapReply)

			ldapRequest.username = sender
			ldapRequest.filter = config.LDAP.Filter
			ldapRequest.guid = h.guid
			ldapRequest.attributes = config.LDAP.ResultAttr
			ldapRequest.replyChan = ldapReplyChan

			ldapRequestChan <- ldapRequest

			ldapReply = <-ldapReplyChan

			if ldapReply.err != nil {
				h.LogError(err)
			} else if resultAttr, ok := ldapReply.result[config.LDAP.ResultAttr[0]]; ok {
				// LDAP single value
				sender = resultAttr[0]
			}
		}

		key := fmt.Sprintf("%s%s", config.RedisPrefix, sender)
		redisHandle.Del(ctx, key).Err()

		h.LogInfo(Sender, sender, "result", "unlocked")
		h.responseWriter.WriteHeader(http.StatusAccepted)
	} else {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errUnknownKey)
	}
}

func (h *HTTP) POSTQuery() {
	var (
		requestData  *Body
		policyResult string
		result       bool
	)

	if !HasContentType(h.request, "application/json") {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errWrongCT)

		return
	}

	body, err := io.ReadAll(h.request.Body)
	if err != nil {
		h.responseWriter.WriteHeader(http.StatusInternalServerError)
		h.LogError(err)

		return
	}

	requestData = &Body{}
	if err = json.Unmarshal(body, requestData); err != nil {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(err)

		return
	}

	if requestData.Key == Client {
		clientRequest, ok := requestData.Value.(map[string]any)
		if !ok {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errValueFormat)

			return
		}

		userAttribute := Sender
		if config.UseSASLUsername {
			userAttribute = SASLUsername
		}

		requiredFieldsFound := false

		if _, addressFound := clientRequest["address"].(string); addressFound {
			if _, senderFound := clientRequest[Sender]; senderFound {
				requiredFieldsFound = true

				policyRequest := map[string]string{
					"request":        "smtpd_access_policy",
					"client_address": clientRequest["address"].(string),
					userAttribute:    clientRequest[Sender].(string),
				}

				policyResult = getPolicyResponse(policyRequest, h.guid)
			}
		}

		if !requiredFieldsFound {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errNoAddressNORSender)

			return
		}
	}

	if policyResult != "action=DUNNO" {
		result = false
	} else {
		result = true
	}

	respone, _ := json.Marshal(&RESTResult{
		GUID:      h.guid,
		Object:    h.request.RemoteAddr,
		Operation: "query",
		Result:    result,
	})

	h.responseWriter.Header().Set("Content-Type", "application/json")
	h.responseWriter.WriteHeader(http.StatusAccepted)
	h.responseWriter.Write(respone)
}

func (h *HTTP) PUTUpdate() {
	if !HasContentType(h.request, "application/json") {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errWrongCT)

		return
	}

	body, err := io.ReadAll(h.request.Body)
	if err != nil {
		h.responseWriter.WriteHeader(http.StatusInternalServerError)
		h.LogError(err)
	} else {
		customSettings := &CustomSettings{}
		if err = json.Unmarshal(body, customSettings); err != nil {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(err)
		} else {
			h.responseWriter.WriteHeader(http.StatusAccepted)
			customSettingsStore.Store(customSettings)

			h.LogInfo("result", "success")
		}
	}
}

func (h *HTTP) PATCHModify() {
	var requestData *Body

	if !HasContentType(h.request, "application/json") {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errWrongCT)

		return
	}

	body, err := io.ReadAll(h.request.Body)
	if err != nil {
		h.responseWriter.WriteHeader(http.StatusInternalServerError)
		h.LogError(err)

		return
	}

	requestData = &Body{}
	//nolint:govet // Ignore
	if err = json.Unmarshal(body, requestData); err != nil {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(err)

		return
	}

	if requestData.Key == Sender {
		account, ok := requestData.Value.(map[string]any)
		if !ok {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(err)

			return
		}

		var (
			comment   string
			countries int
			ips       int
			sender    string
			tempFloat float64
		)

		if val, ok := account["comment"]; ok {
			if comment, ok = val.(string); !ok {
				h.responseWriter.WriteHeader(http.StatusBadRequest)
				h.LogError(errCommentNotString)

				return
			}
		}

		if val, ok := account["countries"]; ok {
			if tempFloat, ok = val.(float64); !ok {
				log.Printf("%T: %v\n", account["countries"], account["countries"])
				h.responseWriter.WriteHeader(http.StatusBadRequest)
				h.LogError(errCountriesNotFloat64)

				return
			}

			countries = int(tempFloat)
		}

		if val, ok := account["ips"]; ok {
			if tempFloat, ok = val.(float64); !ok {
				h.responseWriter.WriteHeader(http.StatusBadRequest)
				h.LogError(errIPsNotFloat64)

				return
			}

			ips = int(tempFloat)
		}

		if val, ok := account[Sender]; ok {
			if sender, ok = val.(string); !ok {
				h.responseWriter.WriteHeader(http.StatusBadRequest)
				h.LogError(errSenderNotString)

				return
			}
		}

		if countries <= 0 {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errCountriesLowerThantZero)

			return
		}

		if ips <= 0 {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errIPsLowerThanZero)

			return
		}

		if sender == "" {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errSenderEmpty)

			return
		}

		if val := os.Getenv("GO_TESTING"); val == "" {
			customSettings := customSettingsStore.Load().(*CustomSettings) //nolint:forcetypeassert // Global variable
			if customSettings != nil {
				for index, record := range customSettings.Data {
					if record.Sender != sender {
						continue
					}

					// Update record
					customSettings.Data[index].IPs = ips
					customSettings.Data[index].Countries = countries
					customSettings.Data[index].Comment = comment

					customSettingsStore.Store(customSettings)
					h.responseWriter.WriteHeader(http.StatusAccepted)
					h.LogInfo("result", "success")

					return
				}

				// Add record
				accountRecord := Account{
					Comment:   comment,
					Sender:    sender,
					IPs:       ips,
					Countries: countries,
				}
				customSettings.Data = append(customSettings.Data, accountRecord)

				customSettingsStore.Store(customSettings)
				h.responseWriter.WriteHeader(http.StatusAccepted)
				h.LogInfo("result", "success")
			} else {
				accountRecord := Account{
					Comment:   comment,
					Sender:    sender,
					IPs:       ips,
					Countries: countries,
				}
				customSettings = &CustomSettings{Data: []Account{accountRecord}}

				customSettingsStore.Store(customSettings)
				h.responseWriter.WriteHeader(http.StatusAccepted)
				h.LogInfo("result", "success")
			}
		}
	}
}

func (h *HTTP) DELETERemove() {
	var requestData *Body

	if !HasContentType(h.request, "application/json") {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errWrongCT)

		return
	}

	body, err := io.ReadAll(h.request.Body)
	if err != nil {
		h.responseWriter.WriteHeader(http.StatusInternalServerError)
		h.LogError(err)

		return
	}

	requestData = &Body{}
	if err = json.Unmarshal(body, requestData); err != nil {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(err)

		return
	}

	if requestData.Key == Sender {
		sender, ok := requestData.Value.(string)
		if !ok {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errValueNotString)

			return
		}

		if sender == "" {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errValueEmpty)

			return
		}

		if val := os.Getenv("GO_TESTING"); val == "" {
			customSettings := customSettingsStore.Load().(*CustomSettings) //nolint:forcetypeassert // Global variable
			if customSettings != nil {
				if len(customSettings.Data) > 0 {
					for index, record := range customSettings.Data {
						if record.Sender != sender {
							continue
						}

						customSettings.Data = func(s []Account, i int) []Account {
							s[i] = s[len(s)-1]

							return s[:len(s)-1]
						}(customSettings.Data, index)

						customSettingsStore.Store(customSettings)
						h.responseWriter.WriteHeader(http.StatusAccepted)
						h.LogInfo("result", "success")

						return
					}

					h.responseWriter.WriteHeader(http.StatusBadRequest)
					h.LogError(errSenderNotFound)
				}
			}
		}
	}
}

func (a *HTTPApp) httpRootPage(responseWriter http.ResponseWriter, request *http.Request) {
	app := &HTTP{
		guid:           ksuid.New().String(),
		responseWriter: responseWriter,
		request:        request,
	}

	switch request.Method {
	case GET:
		switch request.URL.Path {
		case "/reload":
			app.GETReload()
		case "/custom-settings":
			app.GETCustomSettings()
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case POST:
		switch request.URL.Path {
		case "/remove":
			app.POSTRemove()
		case "/query":
			app.POSTQuery()
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case PUT:
		switch request.URL.Path {
		case "/update":
			app.PUTUpdate()
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case PATCH:
		switch request.URL.Path {
		case "/modify":
			app.PATCHModify()
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case DELETE:
		switch request.URL.Path {
		case "/remove":
			app.DELETERemove()
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	default:
		responseWriter.WriteHeader(http.StatusMethodNotAllowed)

		return
	}
}

func (a *HTTPApp) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(a.auth.username))
			expectedPasswordHash := sha256.Sum256([]byte(a.auth.password))

			usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
			passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1

			if usernameMatch && passwordMatch {
				next.ServeHTTP(responseWriter, request)

				return
			}
		}

		responseWriter.Header().Set("WWW-Authenticate", `Basic realm="Protected area", charset="UTF-8"`)
		http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
	}
}

func httpApp() {
	var err error

	app := &config.HTTPApp

	mux := http.NewServeMux()
	if app.useBasicAuth {
		mux.HandleFunc("/", app.basicAuth(app.httpRootPage))
	} else {
		mux.HandleFunc("/", app.httpRootPage)
	}

	www := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", config.HTTPAddress, config.HTTPPort),
		Handler:           mux,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second, //nolint:gomnd // Time factor
		ReadHeaderTimeout: 10 * time.Second, //nolint:gomnd // Time factor
		WriteTimeout:      30 * time.Second, //nolint:gomnd // Time factor
	}

	level.Info(logger).Log("msg", "Starting geoip-policyd HTTP service", "address", www.Addr)

	if app.useSSL {
		err = www.ListenAndServeTLS(app.x509.cert, app.x509.key)
	} else {
		err = www.ListenAndServe()
	}

	level.Error(logger).Log("error", err)
	os.Exit(1)
}
