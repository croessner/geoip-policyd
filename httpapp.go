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
	"fmt"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kit/log/level"
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
	Sender = "sender"
	Client = "client"
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

type httpFunctionParameters struct {
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

func (a *HTTPApp) httpRootPage(responseWriter http.ResponseWriter, request *http.Request) {
	guid := ksuid.New().String()

	parameters := &httpFunctionParameters{guid: guid, responseWriter: responseWriter, request: request}

	switch request.Method {
	case GET:
		switch request.URL.Path {
		case "/reload":
			httpGETReload(parameters)
		case "/custom-settings":
			httpGETCustomSettings(parameters)
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case POST:
		switch request.URL.Path {
		case "/remove":
			httpPOSTRemove(parameters)
		case "/query":
			httpPOSTQuery(parameters)
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case PUT:
		switch request.URL.Path {
		case "/update":
			httpPUTUpdate(parameters)
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case PATCH:
		switch request.URL.Path {
		case "/modify":
			httpPATCHModify(parameters)
		default:
			responseWriter.WriteHeader(http.StatusNotFound)
		}

	case DELETE:
		switch request.URL.Path {
		case "/remove":
			httpDELETERemove(parameters)
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
