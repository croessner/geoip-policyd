// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/go-kit/log/level"
	"github.com/json-iterator/go"
	"github.com/oschwald/maxminddb-golang"
	"github.com/segmentio/ksuid"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

type DovecotPolicyStatus int8

const (
	DovecotPolicyAccept DovecotPolicyStatus = 0
	DovecotPolicyReject DovecotPolicyStatus = -1
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
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// QueryRequest is the typed JSON contract accepted by the /query route.
type QueryRequest struct {
	Key   string          `json:"key"`
	Value QueryClientData `json:"value"`
}

// QueryClientData contains the client identity that is translated into a policy input.
type QueryClientData struct {
	Address string `json:"address"`
	Sender  string `json:"sender"`
}

// QueryResponseObject is the detailed /query response payload returned unless compact mode is requested.
type QueryResponseObject struct {
	RemoteAddr           string   `json:"remote_addr"`
	PolicyReject         bool     `json:"policy_reject"`
	Whitelisted          bool     `json:"whitelisted"`
	CurrentClientIP      string   `json:"current_client_ip"`
	CurrentCountryCode   string   `json:"current_country_code"`
	TotalIPs             int      `json:"total_ips"`
	TotalCountries       int      `json:"total_countries"`
	HomeIPsSeen          []string `json:"home_ips_seen"`
	ForeignIPsSeen       []string `json:"foreign_ips_seen"`
	HomeCountriesSeen    []string `json:"home_countries_seen"`
	ForeignCountriesSeen []string `json:"foreign_countries_seen"`
}

type RESTResult struct {
	GUID      string `json:"guid"`
	Object    any    `json:"object"`
	Operation string `json:"operation"`
	Error     error  `json:"error"`
	Result    any    `json:"result"`
}

type HTTP struct {
	guid           string
	responseWriter http.ResponseWriter
	request        *http.Request
}

type DovecotPolicyResponse struct {
	Status  DovecotPolicyStatus `json:"status"`
	Message string              `json:"msg"`
}

func HasContentType(request *http.Request, mimetype string) bool {
	contentType := request.Header.Get("Content-type")

	for v := range strings.SplitSeq(contentType, ",") {
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
		"query_string", h.request.URL.RawQuery,
		"error", err)
}

// GETReload reloads GeoIP, CDB, and custom settings resources without restarting the HTTP service.
func (h *HTTP) GETReload() {
	var (
		err               error
		customSettings    *CustomSettings
		newCustomSettings *CustomSettings
	)

	reader, err := maxminddb.Open(config.GeoipPath)
	if err != nil {
		h.responseWriter.WriteHeader(http.StatusInternalServerError)
		h.LogError(err)

		return
	}

	geoIP.SwapReader(reader)

	h.LogInfo("file", config.GeoipPath, "result", "reloaded")

	if config.UseCDB {
		var db *cdb.CDB

		db, err = cdb.Open(config.CDBPath)

		if err != nil {
			h.responseWriter.WriteHeader(http.StatusInternalServerError)
			h.LogError(err)

			return
		}

		if olddb := cdbStore.Load().(*cdb.CDB); olddb != nil {
			olddb.Close()
		}

		cdbStore.Store(db)
	}

	if customSettings = loadCustomSettings(); customSettings != nil {
		newCustomSettings = NewCustomSettingsService(config, redisHandle, logger).Load()
		if newCustomSettings != nil {
			storeCustomSettings(newCustomSettings)

			h.LogInfo("file", config.CustomSettingsPath, "result", "reloaded")
		}
	}

	h.responseWriter.WriteHeader(http.StatusAccepted)
}

func (h *HTTP) GETCustomSettings() {
	h.responseWriter.Header().Set("Content-Type", "application/json")

	if customSettings := loadCustomSettings(); customSettings != nil {
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
				ldapReply   *LdapReply
				ldapRequest *LdapRequest
			)

			ldapReplyChan := make(chan *LdapReply)

			ldapRequest = &LdapRequest{}

			ldapRequest.username = sender
			ldapRequest.guid = &h.guid
			ldapRequest.replyChan = ldapReplyChan

			ldapRequestChan <- ldapRequest

			ldapReply = <-ldapReplyChan

			if ldapReply.err != nil {
				h.LogError(err)
			} else if resultAttr, ok := ldapReply.result[config.LdapConf.SearchAttributes[ldapSingleValue]]; ok {
				// LDAP single value
				sender = resultAttr[ldapSingleValue].(string)
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

// POSTQuery handles the public JSON policy query route and translates it into the typed policy hotpath.
func (h *HTTP) POSTQuery() {
	var (
		policyErr   error
		result      bool
		requestData *QueryRequest
	)

	policyResponse := &PolicyResponse{}

	if !HasContentType(h.request, "application/json") {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errWrongCT)

		return
	}

	requestData = &QueryRequest{}
	if err := json.NewDecoder(h.request.Body).Decode(requestData); err != nil {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(err)

		return
	}

	if requestData.Key == Client {
		policyInput, inputErr := NewPolicyInput(requestData.Value.Sender, requestData.Value.Address)
		if inputErr != nil {
			h.responseWriter.WriteHeader(http.StatusBadRequest)
			h.LogError(errNoAddressNORSender)

			return
		}

		info := h.request.URL.Query().Get("info") == "1"
		policyResponse, policyErr = getPolicyResponseFor(policyInput, h.guid, info)
	} else {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errNoClient)

		return
	}

	if policyErr == nil {
		if policyResponse.fired {
			result = false
		} else {
			result = true
		}
	} else {
		_ = level.Error(logger).Log("error", policyErr.Error())

		// Do not block on errors.
		result = true
	}

	var object any

	if policyResponse == nil {
		object = nil
	} else if h.request.URL.Query().Get("compact") == "1" {
		object = Client
	} else {
		object = QueryResponseObject{
			RemoteAddr:           h.request.RemoteAddr,
			PolicyReject:         policyResponse.fired,
			Whitelisted:          policyResponse.whitelisted,
			CurrentClientIP:      policyResponse.currentClientIP,
			CurrentCountryCode:   policyResponse.currentCountryCode,
			TotalIPs:             policyResponse.totalIPs,
			TotalCountries:       policyResponse.totalCountries,
			HomeIPsSeen:          policyResponse.homeIPsSeen,
			ForeignIPsSeen:       policyResponse.foreignIPsSeen,
			HomeCountriesSeen:    policyResponse.homeCountriesSeen,
			ForeignCountriesSeen: policyResponse.foreignCountriesSeen,
		}
	}

	respone, _ := json.Marshal(&RESTResult{
		GUID:      h.guid,
		Object:    object,
		Operation: "query",
		Error:     policyErr,
		Result:    result,
	})

	h.responseWriter.Header().Set("Content-Type", "application/json")
	h.responseWriter.WriteHeader(http.StatusAccepted)
	h.responseWriter.Write(respone)
}

func (h *HTTP) POSTDovecotPolicy() {
	var (
		assertOk bool

		resultCode DovecotPolicyStatus
		result     string

		address string
		sender  string

		policyResponse *PolicyResponse
		dovecotPolicy  map[string]any
	)

	cmd := h.request.URL.Query().Get("command")
	if cmd == "report" {
		respone, _ := json.Marshal(&DovecotPolicyResponse{
			Status:  DovecotPolicyAccept,
			Message: "Nothing to report",
		})

		h.responseWriter.Header().Set("Content-Type", "application/json")
		h.responseWriter.WriteHeader(http.StatusOK)
		h.responseWriter.Write(respone)

		return
	} else if cmd != "allow" {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errOnlyAllowReport)

		return
	}

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

	dovecotPolicy = make(map[string]any)
	if err = json.Unmarshal(body, &dovecotPolicy); err != nil {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(err)

		return
	}

	level.Debug(logger).Log(
		"guid", h.guid, "msg", "dovecot policy request", "policy", fmt.Sprintf("%+v", dovecotPolicy))

	if address, assertOk = dovecotPolicy["remote"].(string); !assertOk || address == "" {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errNoAddressNORSender)

		return
	}

	if sender, assertOk = dovecotPolicy["login"].(string); !assertOk || sender == "" {
		h.responseWriter.WriteHeader(http.StatusBadRequest)
		h.LogError(errNoAddressNORSender)

		return
	}

	userAttribute := Sender

	if config.UseSASLUsername {
		userAttribute = SASLUsername
	}

	policyRequest := map[string]string{
		"request":        "smtpd_access_policy",
		"client_address": address,
		userAttribute:    sender,
	}

	// Check if info parameter is present in the query string
	infoParam := h.request.URL.Query().Get("info")
	info := infoParam == "1"

	policyResponse, err = getPolicyResponse(policyRequest, h.guid, info)

	if err == nil {
		if policyResponse.fired {
			result = rejectText
			resultCode = DovecotPolicyReject
		} else {
			result = "ok"
			resultCode = DovecotPolicyAccept
		}
	} else {
		level.Error(logger).Log("guid", h.guid, "error", err.Error())
		h.responseWriter.WriteHeader(http.StatusInternalServerError)

		return
	}

	respone, _ := json.Marshal(&DovecotPolicyResponse{
		Status:  resultCode,
		Message: result,
	})

	h.responseWriter.Header().Set("Content-Type", "application/json")
	h.responseWriter.WriteHeader(http.StatusOK)
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
			storeCustomSettings(customSettings)

			h.LogInfo("result", "success")
		}
	}
}

func (h *HTTP) PATCHModify() {
	if !HasContentType(h.request, "application/json") {
		h.respondWithError(http.StatusBadRequest, errWrongCT)

		return
	}

	body, err := io.ReadAll(h.request.Body)
	if err != nil {
		h.respondWithError(http.StatusInternalServerError, err)

		return
	}

	var requestData Body
	if err := json.Unmarshal(body, &requestData); err != nil {
		h.respondWithError(http.StatusBadRequest, err)

		return
	}

	if requestData.Key != Sender {
		return
	}

	accountData, ok := requestData.Value.(map[string]any)
	if !ok {
		h.respondWithError(http.StatusBadRequest, err)

		return
	}

	comment, countries, ips, sender := h.extractAccountData(accountData)

	if err = h.validateAccountData(countries, ips, sender); err != nil {
		h.respondWithError(http.StatusBadRequest, err)

		return
	}

	// TODO: Update home_countries settings
	h.updateOrAddAccountData(comment, countries, ips, sender)
	h.responseWriter.WriteHeader(http.StatusAccepted)
	h.LogInfo("result", "success")
}

func (h *HTTP) respondWithError(statusCode int, err error) {
	h.responseWriter.WriteHeader(statusCode)
	h.LogError(err)
}

func (h *HTTP) extractAccountData(accountData map[string]any) (string, int, int, string) {
	comment := h.extractString(accountData, "comment", errCommentNotString)
	countries := h.extractInt(accountData, "countries", errCountriesNotFloat64)
	ips := h.extractInt(accountData, "ips", errIPsNotFloat64)
	sender := h.extractString(accountData, Sender, errSenderNotString)

	return comment, countries, ips, sender
}

func (h *HTTP) extractInt(accountData map[string]any, key string, err error) int {
	if value, ok := accountData[key]; ok {
		if floatValue, ok := value.(float64); ok {
			return int(floatValue)
		}

		h.respondWithError(http.StatusBadRequest, err)
	}

	return 0
}

func (h *HTTP) extractString(accountData map[string]any, key string, err error) string {
	if value, ok := accountData[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}

		h.respondWithError(http.StatusBadRequest, err)
	}

	return ""
}

func (h *HTTP) extractHome(accountData map[string]any) *HomeCountries {
	if home, ok := accountData["home_countries"]; ok {
		homeCountries := &HomeCountries{}

		err := json.Unmarshal([]byte(home.(string)), homeCountries)
		if err != nil {
			return nil
		}

		return homeCountries
	}

	return nil
}

func (h *HTTP) validateAccountData(countries, ips int, sender string) error {
	if countries <= 0 {
		return errCountriesLowerThantZero
	}

	if ips <= 0 {
		return errIPsLowerThanZero
	}

	if sender == "" {
		return errSenderEmpty
	}

	return nil
}

func (h *HTTP) updateOrAddAccountData(comment string, countries, ips int, sender string) {
	if os.Getenv("GO_TESTING") == "" {
		customSettings := loadCustomSettings()
		if customSettings != nil {
			customSettings = customSettings.Clone()
			for index, record := range customSettings.Data {
				if record.Sender == sender {
					h.updateRecord(&customSettings.Data[index], comment, countries, ips)
					storeCustomSettings(customSettings)

					return
				}
			}

			h.addAccountRecord(customSettings, comment, countries, ips, sender)
		} else {
			h.createAndStoreNewSettings(comment, countries, ips, sender)
		}
	} else {
		h.responseWriter.WriteHeader(http.StatusNoContent)
	}
}

func (h *HTTP) updateRecord(record *Account, comment string, countries, ips int) {
	record.Comment = comment
	record.Countries = countries
	record.IPs = ips
}

func (h *HTTP) addAccountRecord(settings *CustomSettings, comment string, countries, ips int, sender string) {
	accountRecord := Account{Comment: comment, Sender: sender, Countries: countries, IPs: ips}
	settings.Data = append(settings.Data, accountRecord)

	storeCustomSettings(settings)
}

func (h *HTTP) createAndStoreNewSettings(comment string, countries, ips int, sender string) {
	accountRecord := Account{Comment: comment, Sender: sender, Countries: countries, IPs: ips}
	newSettings := &CustomSettings{Data: []Account{accountRecord}}

	storeCustomSettings(newSettings)
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
			customSettings := loadCustomSettings()
			if customSettings != nil {
				customSettings = customSettings.Clone()
				if len(customSettings.Data) > 0 {
					for index, record := range customSettings.Data {
						if record.Sender != sender {
							continue
						}

						customSettings.Data = func(s []Account, i int) []Account {
							s[i] = s[len(s)-1]

							return s[:len(s)-1]
						}(customSettings.Data, index)

						storeCustomSettings(customSettings)
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
		case "/dovecotpolicy":
			app.POSTDovecotPolicy()
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
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
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
