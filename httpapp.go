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
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	GET  = "GET"
	POST = "POST"
)

// HttpApp Basic Auth for the HTTP service
type HttpApp struct {
	Auth struct {
		Username string
		Password string
	}
	X509 struct {
		Cert string
		Key  string
	}
	UseBasicAuth bool
	UseSSL       bool
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

			//goland:noinspection GoUnhandledErrorResult
			geoip.Reader.Close()
			geoip.Reader, err = maxminddb.Open(cfg.GeoipPath)
			if err != nil {
				log.Fatal("Error: Can not open GeoLite2-City database file", err)
			}
			log.Println("Reloaded GeoLite2-City database file")

			if cs != nil {
				cs = initCustomSettings(cfg)
				log.Println("Reloaded custom settings file")
			}

			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(rw, "OK reload")

		case "/custom-settings":
			if cs == nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(rw, "[]")
				return
			}
			if jsonValue, err := json.Marshal(cs.Data); err != nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(rw, "[]")
			} else {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintf(rw, "%+v\n", string(jsonValue))
			}
		}

	case POST:
		switch uri.Path {
		case "/remove":
			log.Println("sender:", request.FormValue("sender"))
			if val, ok := values["sender"]; ok {
				sender := val[0]
				if sender == "" {
					//goland:noinspection GoUnhandledErrorResult
					fmt.Fprintln(rw, "[]")
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

					if ldapResult, err = ldapServer.Search(sender); err != nil {
						log.Println("Info:", err)
						if !strings.Contains(fmt.Sprint(err), "No Such Object") {
							if ldapServer.LDAPConn == nil {
								ldapServer.Connect()
								ldapServer.Bind()
								ldapResult, _ = ldapServer.Search(sender)
							}
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
				fmt.Fprintf(rw, "Sender '%s' unlocked", sender)
			} else {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(rw, "[]")
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
			expectedUsernameHash := sha256.Sum256([]byte(a.Auth.Username))
			expectedPasswordHash := sha256.Sum256([]byte(a.Auth.Password))

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
	if app.UseBasicAuth {
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
	if app.UseSSL {
		err = www.ListenAndServeTLS(app.X509.Cert, app.X509.Key)
	} else {
		err = www.ListenAndServe()
	}
	log.Fatalln("Error:", err)
}
