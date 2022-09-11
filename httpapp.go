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

const Sender = "sender"

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

//nolint:gocognit,gocyclo,maintidx // Ignore complexity
func (a *HTTPApp) httpRootPage(responseWriter http.ResponseWriter, request *http.Request) {
	method := request.Method
	uri := request.URL
	client := request.RemoteAddr
	guid := ksuid.New().String()

	switch method {
	case GET:
		switch uri.Path {
		case "/reload":
			var (
				err               error
				customSettings    *CustomSettings
				newCustomSettings *CustomSettings
			)

			geoip := &GeoIP{}
			geoip.Reader, err = maxminddb.Open(config.GeoipPath)

			if err != nil {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				level.Error(logger).Log(
					"guid", guid,
					"client", client,
					"request", method,
					"path", uri.Path,
					"error", err.Error())

				return
			}

			geoIPStore.Store(geoip)

			level.Info(logger).Log(
				"guid", guid,
				"client", client,
				"request", method,
				"path", uri.Path,
				"file", config.GeoipPath,
				"result", "reloaded")

			//nolint:forcetypeassert // Global variable
			if customSettings = customSettingsStore.Load().(*CustomSettings); customSettings != nil {
				newCustomSettings = initCustomSettings(config)
				if newCustomSettings != nil {
					customSettingsStore.Store(newCustomSettings)

					level.Info(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"file", config.CustomSettingsPath,
						"result", "reloaded")
				}
			}

			responseWriter.WriteHeader(http.StatusAccepted)

		case "/custom-settings":
			responseWriter.Header().Set("Content-Type", "application/json")

			//nolint:forcetypeassert // Global variable
			if customSettings := customSettingsStore.Load().(*CustomSettings); customSettings != nil {
				if err := json.NewEncoder(responseWriter).Encode(customSettings.Data); err != nil {
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"error", err.Error())

					return
				}

				level.Info(logger).Log(
					"guid", guid, "client", client, "request", method, "path", uri.Path)
			} else {
				responseWriter.WriteHeader(http.StatusNoContent)

				level.Info(logger).Log(
					"guid", guid, "client", client, "request", method, "path", uri.Path)
			}

		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case POST:
		switch uri.Path {
		case "/remove":
			var requestData *Body

			if !HasContentType(request, "application/json") {
				responseWriter.WriteHeader(http.StatusBadRequest)
				level.Error(logger).Log(
					"guid", guid,
					"client", client,
					"request", method,
					"path", uri.Path,
					"error", "wrong Content-Type header")

				return
			}

			body, err := io.ReadAll(request.Body)
			if err != nil {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				level.Error(logger).Log(
					"guid", guid, "client", client, "request", method, "path", uri.Path, "error", err.Error())

				return
			}

			requestData = &Body{}
			if err := json.Unmarshal(body, requestData); err != nil {
				responseWriter.WriteHeader(http.StatusBadRequest)
				level.Error(logger).Log(
					"guid", guid, "client", client, "request", method, "path", uri.Path, "error", err.Error())

				return
			}

			if requestData.Key == Sender {
				sender, ok := requestData.Value.(string)
				if !ok {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"error", "value must be string")

					return
				}

				if sender == "" {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"error", "value must not be empty")

					return
				}

				if config.UseLDAP {
					var (
						err         error
						ldapReply   LdapReply
						ldapRequest LdapRequest
					)

					ldapReplyChan := make(chan LdapReply)

					ldapRequest.username = sender
					ldapRequest.filter = config.LDAP.Filter
					ldapRequest.guid = guid
					ldapRequest.attributes = config.LDAP.ResultAttr
					ldapRequest.replyChan = ldapReplyChan

					ldapRequestChan <- ldapRequest

					ldapReply = <-ldapReplyChan

					if ldapReply.err != nil {
						level.Error(logger).Log("guid", guid, "error", err.Error())
					} else if resultAttr, ok := ldapReply.result[config.LDAP.ResultAttr[0]]; ok {
						// LDAP single value
						sender = resultAttr[0]
					}
				}

				key := fmt.Sprintf("%s%s", config.RedisPrefix, sender)
				redisHandle.Del(ctx, key).Err()

				level.Info(logger).Log(
					"guid", guid,
					"client", client,
					"request", method,
					"path", uri.Path,
					"sender", sender,
					"result", "unlocked")

				responseWriter.WriteHeader(http.StatusAccepted)
			} else {
				responseWriter.WriteHeader(http.StatusBadRequest)
				level.Error(logger).Log(
					"guid", guid, "client", client, "request", method, "path", uri.Path, "error", "unknown key")
			}

		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case PUT:
		switch uri.Path {
		case "/update":
			if !HasContentType(request, "application/json") {
				responseWriter.WriteHeader(http.StatusBadRequest)
				level.Error(logger).Log(
					"guid", guid,
					"client", client,
					"request", method,
					"path", uri.Path,
					"error", "wrong Content-Type header")

				return
			}

			body, err := io.ReadAll(request.Body)
			if err != nil {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				level.Error(logger).Log(
					"guid", guid, "client", client, "request", method, "path", uri.Path, "error", err.Error())
			} else {
				customSettings := &CustomSettings{}
				if err := json.Unmarshal(body, customSettings); err != nil {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid, "client", client, "request", method, "path", uri.Path, "error", err.Error())
				} else {
					responseWriter.WriteHeader(http.StatusAccepted)
					customSettingsStore.Store(customSettings)

					level.Info(logger).Log(
						"guid", guid, "client", client, "request", method, "path", uri.Path, "result", "success")
				}
			}

		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case PATCH:
		switch uri.Path {
		case "/modify":
			var requestData *Body

			if !HasContentType(request, "application/json") {
				responseWriter.WriteHeader(http.StatusBadRequest)
				level.Error(logger).Log(
					"guid", guid,
					"client", client,
					"request", method,
					"path", uri.Path,
					"error", "wrong Content-Type header")

				return
			}

			body, err := io.ReadAll(request.Body)
			if err != nil {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				level.Error(logger).Log(
					"guid", guid, "client", client, "request", method, "path", uri.Path, "error", err.Error())
			} else {
				requestData = &Body{}
				//nolint:govet // Ignore
				if err := json.Unmarshal(body, requestData); err != nil {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid, "client", client, "request", method, "path", uri.Path, "error", err.Error())

					return
				}
			}

			if requestData.Key == Sender {
				account, ok := requestData.Value.(map[string]any)
				if !ok {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid, "client", client, "request", method, "path", uri.Path, "error", err.Error())

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
						responseWriter.WriteHeader(http.StatusBadRequest)
						level.Error(logger).Log(
							"guid", guid,
							"client", client,
							"request", method,
							"path", uri.Path,
							"error", "'comment' is not a string")

						return
					}
				}

				if val, ok := account["countries"]; ok {
					if tempFloat, ok = val.(float64); !ok {
						log.Printf("%T: %v\n", account["countries"], account["countries"])
						responseWriter.WriteHeader(http.StatusBadRequest)
						level.Error(logger).Log(
							"guid", guid,
							"client", client,
							"request", method,
							"path", uri.Path,
							"error", "'countries' is not a float64")

						return
					}

					countries = int(tempFloat)
				}

				if val, ok := account["ips"]; ok {
					if tempFloat, ok = val.(float64); !ok {
						responseWriter.WriteHeader(http.StatusBadRequest)
						level.Error(logger).Log(
							"guid", guid,
							"client", client,
							"request", method,
							"path", uri.Path,
							"error", "'ips' is not a float64")

						return
					}

					ips = int(tempFloat)
				}

				if val, ok := account[Sender]; ok {
					if sender, ok = val.(string); !ok {
						responseWriter.WriteHeader(http.StatusBadRequest)
						level.Error(logger).Log(
							"guid", guid,
							"client", client,
							"request", method,
							"path", uri.Path,
							"error", "'sender' is not a string")

						return
					}
				}

				if countries <= 0 {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"error", "'countries' lower than zero",
						"countries", countries)

					return
				}

				if ips <= 0 {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"error", "'ips' lower than zero",
						"ips", ips)

					return
				}

				if sender == "" {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"error", "'sender' is empty")

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
							responseWriter.WriteHeader(http.StatusAccepted)

							level.Info(logger).Log(
								"guid", guid,
								"client", client,
								"request", method,
								"path", uri.Path,
								"result", "success")

							return
						}

						// Add record
						account := Account{Comment: comment, Sender: sender, IPs: ips, Countries: countries}
						customSettings.Data = append(customSettings.Data, account)

						customSettingsStore.Store(customSettings)
						responseWriter.WriteHeader(http.StatusAccepted)

						level.Info(logger).Log(
							"guid", guid,
							"client", client,
							"request", method,
							"path", uri.Path,
							"result", "success")
					} else {
						account := Account{Comment: comment, Sender: sender, IPs: ips, Countries: countries}
						customSettings = &CustomSettings{Data: []Account{account}}

						customSettingsStore.Store(customSettings)
						responseWriter.WriteHeader(http.StatusAccepted)

						level.Info(logger).Log(
							"guid", guid,
							"client", client,
							"request", method,
							"path", uri.Path,
							"result", "success")
					}
				}
			}

		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case DELETE:
		switch uri.Path {
		case "/remove":
			var requestData *Body

			if !HasContentType(request, "application/json") {
				responseWriter.WriteHeader(http.StatusBadRequest)
				level.Error(logger).Log(
					"guid", guid,
					"client", client,
					"request", method,
					"path", uri.Path,
					"error", "wrong Content-Type header")

				return
			}

			body, err := io.ReadAll(request.Body)
			if err != nil {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				level.Error(logger).Log(
					"guid", guid,
					"client", client,
					"request", method,
					"path", uri.Path,
					"error", err.Error())
			} else {
				requestData = &Body{}
				if err := json.Unmarshal(body, requestData); err != nil {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid, "client", client, "request", method, "path", uri.Path, "error", err.Error())

					return
				}
			}

			if requestData.Key == Sender {
				sender, ok := requestData.Value.(string)
				if !ok {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"error", "value must be string")

					return
				}

				if sender == "" {
					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", uri.Path,
						"error", "value must not be empty")

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
								responseWriter.WriteHeader(http.StatusAccepted)

								level.Info(logger).Log(
									"guid", guid,
									"client", client,
									"request", method,
									"path", uri.Path,
									"result", "success")

								return
							}

							responseWriter.WriteHeader(http.StatusBadRequest)
							level.Error(logger).Log(
								"guid", guid,
								"client", client,
								"request", method,
								"path", uri.Path,
								"error", "sender not found",
								"sender", sender)
						}
					}
				}
			}

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

	level.Error(logger).Log("error", err.Error())
	os.Exit(1)
}
