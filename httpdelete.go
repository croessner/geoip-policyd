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
	"encoding/json"
	"github.com/go-kit/log/level"
	"io"
	"net/http"
	"os"
)

func httpDELETERemove(parameters *httpFunctionParameters) {
	var requestData *Body

	guid := parameters.guid
	responseWriter := parameters.responseWriter
	request := parameters.request
	method := request.Method
	client := request.RemoteAddr

	if !HasContentType(request, "application/json") {
		responseWriter.WriteHeader(http.StatusBadRequest)
		level.Error(logger).Log(
			"guid", guid,
			"client", client,
			"request", method,
			"path", request.URL.Path,
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
			"path", request.URL.Path,
			"error", err.Error())
	} else {
		requestData = &Body{}
		if err := json.Unmarshal(body, requestData); err != nil {
			responseWriter.WriteHeader(http.StatusBadRequest)
			level.Error(logger).Log(
				"guid", guid, "client", client, "request", method, "path", request.URL.Path, "error", err.Error())

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
				"path", request.URL.Path,
				"error", "value must be string")

			return
		}

		if sender == "" {
			responseWriter.WriteHeader(http.StatusBadRequest)
			level.Error(logger).Log(
				"guid", guid,
				"client", client,
				"request", method,
				"path", request.URL.Path,
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
							"path", request.URL.Path,
							"result", "success")

						return
					}

					responseWriter.WriteHeader(http.StatusBadRequest)
					level.Error(logger).Log(
						"guid", guid,
						"client", client,
						"request", method,
						"path", request.URL.Path,
						"error", "sender not found",
						"sender", sender)
				}
			}
		}
	}
}
