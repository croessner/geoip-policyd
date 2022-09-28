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
	"log"
	"net/http"
	"os"
)

func httpPATCHModify(parameters *httpFunctionParameters) {
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
			"guid", guid, "client", client, "request", method, "path", request.URL.Path, "error", err.Error())
	} else {
		requestData = &Body{}
		//nolint:govet // Ignore
		if err := json.Unmarshal(body, requestData); err != nil {
			responseWriter.WriteHeader(http.StatusBadRequest)
			level.Error(logger).Log(
				"guid", guid, "client", client, "request", method, "path", request.URL.Path, "error", err.Error())

			return
		}
	}

	if requestData.Key == Sender {
		account, ok := requestData.Value.(map[string]any)
		if !ok {
			responseWriter.WriteHeader(http.StatusBadRequest)
			level.Error(logger).Log(
				"guid", guid, "client", client, "request", method, "path", request.URL.Path, "error", err.Error())

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
					"path", request.URL.Path,
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
					"path", request.URL.Path,
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
					"path", request.URL.Path,
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
					"path", request.URL.Path,
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
				"path", request.URL.Path,
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
				"path", request.URL.Path,
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
				"path", request.URL.Path,
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
						"path", request.URL.Path,
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
					"path", request.URL.Path,
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
					"path", request.URL.Path,
					"result", "success")
			}
		}
	}
}
