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
)

func httpPUTUpdate(parameters *httpFunctionParameters) {
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
		customSettings := &CustomSettings{}
		if err := json.Unmarshal(body, customSettings); err != nil {
			responseWriter.WriteHeader(http.StatusBadRequest)
			level.Error(logger).Log(
				"guid", guid, "client", client, "request", method, "path", request.URL.Path, "error", err.Error())
		} else {
			responseWriter.WriteHeader(http.StatusAccepted)
			customSettingsStore.Store(customSettings)

			level.Info(logger).Log(
				"guid", guid, "client", client, "request", method, "path", request.URL.Path, "result", "success")
		}
	}
}
