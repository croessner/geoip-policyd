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
	"net/http"
	"strings"
	"time"
)

const (
	GET  = "GET"
	POST = "POST"
	PUT  = "PUT"
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

func (a *HttpApp) httpRootPage(rw http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		log.Println("Error:", err)
		return
	}

	method := request.Method
	values := request.Form
	uri := request.URL

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
				log.Fatal("Error: Can not open GeoLite2-City database file", err)
			}
			gi.Store(geoip)
			if cfg.Verbose >= logLevelInfo {
				log.Printf("Info: request='%s'; path='%s'; result='GeoLite2-City reloaded'", method, uri.Path)
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

		case "/custom-settings":
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusCreated)
			if customSettings := cs.Load().(*CustomSettings); customSettings != nil {
				if err := json.NewEncoder(rw).Encode(customSettings.Data); err != nil {
					//goland:noinspection GoUnhandledErrorResult
					fmt.Fprintln(rw, "[]")
					if cfg.Verbose >= logLevelInfo {
						log.Printf("Info: request='%s'; path='%s'; result='failed'", method, uri.Path)
					}
				} else {
					if cfg.Verbose >= logLevelInfo {
						log.Printf("Info: request='%s'; path='%s'; result='success'", method, uri.Path)
					}
				}
			} else {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(rw, "[]")
				if cfg.Verbose >= logLevelInfo {
					log.Printf("Info: request='%s'; path='%s'; result='success'", method, uri.Path)
				}
			}
		}

	case POST:
		switch uri.Path {
		case "/remove":
			if val, ok := values["sender"]; ok {
				sender := val[0]
				if sender == "" {
					//goland:noinspection GoUnhandledErrorResult
					fmt.Fprintln(rw, "Unable to handle request")
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
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintf(rw, "Sender '%s' unlocked\n", sender)
			} else {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(rw, "Unable to handle request")
			}
		}

	case PUT:
		switch uri.Path {
		case "/update":
			body, err := ioutil.ReadAll(request.Body)
			if err != nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(rw, "Unable to handle request:", err)
			} else {
				customSettings := new(CustomSettings)
				if err := json.Unmarshal(body, customSettings); err != nil {
					//goland:noinspection GoUnhandledErrorResult
					fmt.Fprintln(rw, "Unable to handle request:", err)
				} else {
					cs.Store(customSettings)
				}
			}
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
