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
	"github.com/gomodule/redigo/redis"
	"github.com/oschwald/maxminddb-golang"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	GET    = "GET"
	POST   = "POST"
	PUT    = "PUT"
	PATCH  = "PATCH"
	DELETE = "DELETE"
)

// HttpApp Basic auth for the HTTP service
type HttpApp struct {
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

func (a *HttpApp) httpRootPage(rw http.ResponseWriter, request *http.Request) {
	/*
		if err := request.ParseForm(); err != nil {
			log.Println("Error:", err)
			return
		}
	*/

	method := request.Method
	uri := request.URL
	client := request.RemoteAddr

	switch method {
	case GET:
		switch uri.Path {
		case "/reload":
			var err error
			var customSettings *CustomSettings
			var newCustomSettings *CustomSettings

			geoip := new(GeoIP)
			geoip.Reader, err = maxminddb.Open(cfg.GeoipPath)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
				return
			}
			gi.Store(geoip)
			if cfg.Verbose >= logLevelInfo {
				log.Printf("Info: client=%s; request='%s'; path='%s'; result='%s reloaded'", client, method, uri.Path, cfg.GeoipPath)
			}

			if customSettings = cs.Load().(*CustomSettings); customSettings != nil {
				newCustomSettings = initCustomSettings(cfg)
				if newCustomSettings != nil {
					cs.Store(newCustomSettings)
					if cfg.Verbose >= logLevelInfo {
						log.Printf("Info: request='%s'; path='%s'; result='%s reloaded'", method, uri.Path, cfg.CustomSettingsPath)
					}
				}
			}
			rw.WriteHeader(http.StatusAccepted)

		case "/custom-settings":
			rw.Header().Set("Content-Type", "application/json")

			if customSettings := cs.Load().(*CustomSettings); customSettings != nil {
				if err := json.NewEncoder(rw).Encode(customSettings.Data); err != nil {
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
					return
				} else {
					if cfg.Verbose >= logLevelInfo {
						log.Printf("Info: client=%s; request='%s'; path='%s'; result='success'", client, method, uri.Path)
					}
				}
			} else {
				rw.WriteHeader(http.StatusNoContent)
				if cfg.Verbose >= logLevelInfo {
					log.Printf("Info: client=%s; request='%s'; path='%s'; result='success'", client, method, uri.Path)
				}
			}

		default:
			rw.WriteHeader(http.StatusNotFound)
		}

	case POST:
		switch uri.Path {
		case "/remove":
			var requestData *Body

			if !HasContentType(request, "application/json") {
				rw.WriteHeader(http.StatusBadRequest)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='wrong Content-Type header'", client, method, uri.Path)
				return
			}

			body, err := ioutil.ReadAll(request.Body)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
				return
			} else {
				requestData = new(Body)
				if err := json.Unmarshal(body, requestData); err != nil {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
					return
				}
			}

			if requestData.Key == "sender" {
				sender, ok := requestData.Value.(string)
				if !ok {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='value must be string'", client, method, uri.Path)
					return
				}
				if sender == "" {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='value must not be emtpy'", client, method, uri.Path)
					return
				}
				var redisHelper = &Redis{}
				redisConnW := redisHelper.WriteConn()

				//goland:noinspection GoUnhandledErrorResult
				defer redisConnW.Close()

				if cfg.UseLDAP {
					var err error
					var ldapResult string

					ldapServer := &cfg.LDAP

					if ldapResult, err = ldapServer.search(sender); err != nil {
						log.Println("Info:", err)
						if !strings.Contains(fmt.Sprint(err), "No Such Object") {
							ldapServer.LDAPConn.Close()
							ldapServer.connect()
							ldapServer.bind()
							ldapResult, _ = ldapServer.search(sender)
						}
					}
					if ldapResult != "" {
						sender = ldapResult
					}

				}

				key := fmt.Sprintf("%s%s", cfg.RedisPrefix, sender)
				if _, err := redisConnW.Do("DEL",
					redis.Args{}.Add(key)...); err != nil {
					log.Println("Error:", err)
				}
				if cfg.Verbose >= logLevelInfo {
					log.Printf("Info: client=%s; request='%s'; path='%s'; result='%s unlocked'", client, method, uri.Path, sender)
				}
				rw.WriteHeader(http.StatusAccepted)
			} else {
				rw.WriteHeader(http.StatusBadRequest)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='unknown key'", client, method, uri.Path)
			}

		default:
			rw.WriteHeader(http.StatusNotFound)
		}

	case PUT:
		switch uri.Path {
		case "/update":
			if !HasContentType(request, "application/json") {
				rw.WriteHeader(http.StatusBadRequest)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='wrong Content-Type header'", client, method, uri.Path)
				return
			}

			body, err := ioutil.ReadAll(request.Body)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
			} else {
				customSettings := new(CustomSettings)
				if err := json.Unmarshal(body, customSettings); err != nil {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
				} else {
					rw.WriteHeader(http.StatusAccepted)
					cs.Store(customSettings)
					if cfg.Verbose >= logLevelInfo {
						log.Printf("Info: client=%s; request='%s'; path='%s'; result='success'", client, method, uri.Path)
					}
				}
			}

		default:
			rw.WriteHeader(http.StatusNotFound)
		}

	case PATCH:
		switch uri.Path {
		case "/modify":
			var requestData *Body

			if !HasContentType(request, "application/json") {
				rw.WriteHeader(http.StatusBadRequest)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='wrong Content-Type header'", client, method, uri.Path)
				return
			}

			body, err := ioutil.ReadAll(request.Body)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
			} else {
				requestData = new(Body)
				if err := json.Unmarshal(body, requestData); err != nil {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
					return
				}
			}

			if requestData.Key == "sender" {
				account, ok := requestData.Value.(map[string]interface{})
				if !ok {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='value must be account'", client, method, uri.Path)
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
						rw.WriteHeader(http.StatusBadRequest)
						log.Printf("Error: client=%s; request='%s'; path='%s'; result='comment not string'", client, method, uri.Path)
						return
					}
				}
				if val, ok := account["countries"]; ok {
					if tempFloat, ok = val.(float64); !ok {
						log.Printf("%T: %v\n", account["countries"], account["countries"])
						rw.WriteHeader(http.StatusBadRequest)
						log.Printf("Error: client=%s; request='%s'; path='%s'; result='countries not float64'", client, method, uri.Path)
						return
					} else {
						countries = int(tempFloat)
					}
				}
				if val, ok := account["ips"]; ok {
					if tempFloat, ok = val.(float64); !ok {
						rw.WriteHeader(http.StatusBadRequest)
						log.Printf("Error: client=%s; request='%s'; path='%s'; result='ips not float64'", client, method, uri.Path)
						return
					} else {
						ips = int(tempFloat)
					}
				}
				if val, ok := account["sender"]; ok {
					if sender, ok = val.(string); !ok {
						rw.WriteHeader(http.StatusBadRequest)
						log.Printf("Error: client=%s; request='%s'; path='%s'; result='sender not string'", client, method, uri.Path)
						return
					}
				}
				if countries <= 0 {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='countries %d <= 0'", client, method, uri.Path, countries)
					return
				}
				if ips <= 0 {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='ips %d <= 0'", client, method, uri.Path, ips)
					return
				}
				if sender == "" {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='empty sender'", client, method, uri.Path)
					return
				}

				if val := os.Getenv("GO_TESTING"); val == "" {
					customSettings := cs.Load().(*CustomSettings)
					if customSettings != nil {
						for i, record := range customSettings.Data {
							if record.Sender == sender {
								// Update record
								customSettings.Data[i].Ips = ips
								customSettings.Data[i].Countries = countries
								customSettings.Data[i].Comment = comment
								cs.Store(customSettings)
								rw.WriteHeader(http.StatusAccepted)
								log.Printf("Info: client=%s; request='%s'; path='%s'; result='success'", client, method, uri.Path)
								return
							}
						}
						// Add record
						account := Account{Comment: comment, Sender: sender, Ips: ips, Countries: countries}
						customSettings.Data = append(customSettings.Data, account)
						cs.Store(customSettings)
						rw.WriteHeader(http.StatusAccepted)
						log.Printf("Info: client=%s; request='%s'; path='%s'; result='success'", client, method, uri.Path)
					} else {
						account := Account{Comment: comment, Sender: sender, Ips: ips, Countries: countries}
						customSettings = &CustomSettings{Data: []Account{account}}
						cs.Store(customSettings)
						rw.WriteHeader(http.StatusAccepted)
						log.Printf("Info: client=%s; request='%s'; path='%s'; result='success'", client, method, uri.Path)
					}
				}
			}

		default:
			rw.WriteHeader(http.StatusNotFound)
		}

	case DELETE:
		switch uri.Path {
		case "/remove":
			var requestData *Body

			if !HasContentType(request, "application/json") {
				rw.WriteHeader(http.StatusBadRequest)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='wrong Content-Type header'", client, method, uri.Path)
				return
			}

			body, err := ioutil.ReadAll(request.Body)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
			} else {
				requestData = new(Body)
				if err := json.Unmarshal(body, requestData); err != nil {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s'", client, method, uri.Path, err)
					return
				}
			}

			if requestData.Key == "sender" {
				sender, ok := requestData.Value.(string)
				if !ok {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='value must be string'", client, method, uri.Path)
					return
				}
				if sender == "" {
					rw.WriteHeader(http.StatusBadRequest)
					log.Printf("Error: client=%s; request='%s'; path='%s'; result='value must not be emtpy'", client, method, uri.Path)
					return
				}

				if val := os.Getenv("GO_TESTING"); val == "" {
					customSettings := cs.Load().(*CustomSettings)
					if customSettings != nil {
						if len(customSettings.Data) > 0 {
							for i, record := range customSettings.Data {
								if record.Sender == sender {
									customSettings.Data = func(s []Account, i int) []Account {
										s[i] = s[len(s)-1]
										return s[:len(s)-1]
									}(customSettings.Data, i)
									cs.Store(customSettings)
									rw.WriteHeader(http.StatusAccepted)
									log.Printf("Info: client=%s; request='%s'; path='%s'; result='success'", client, method, uri.Path)
									return
								}
							}
							rw.WriteHeader(http.StatusBadRequest)
							log.Printf("Error: client=%s; request='%s'; path='%s'; result='%s not found'", client, method, uri.Path, sender)
						}
					}
				}
			}

		default:
			rw.WriteHeader(http.StatusNotFound)
		}

	default:
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (a *HttpApp) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(a.auth.username))
			expectedPasswordHash := sha256.Sum256([]byte(a.auth.password))

			usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
			passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1

			if usernameMatch && passwordMatch {
				next.ServeHTTP(rw, request)
				return
			}
		}

		rw.Header().Set("WWW-Authenticate", `Basic realm="Protected area", charset="UTF-8"`)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	}
}

func httpApp() {
	var err error
	app := &cfg.HttpApp

	mux := http.NewServeMux()
	if app.useBasicAuth {
		mux.HandleFunc("/", app.basicAuth(app.httpRootPage))
	} else {
		mux.HandleFunc("/", app.httpRootPage)
	}

	www := &http.Server{
		Addr:         cfg.HttpAddress,
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("Starting geoip-policyd HTTP service with address: '%s'", www.Addr)
	if app.useSSL {
		err = www.ListenAndServeTLS(app.x509.cert, app.x509.key)
	} else {
		err = www.ListenAndServe()
	}
	log.Fatalln("Error:", err)
}
