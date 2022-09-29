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
	"net/http"

	"github.com/go-kit/log/level"
	"github.com/oschwald/maxminddb-golang"
)

func httpGETReload(httpFuncArgs *HTTPFuncArgs) {
	var (
		err               error
		customSettings    *CustomSettings
		newCustomSettings *CustomSettings
	)

	guid := httpFuncArgs.guid
	responseWriter := httpFuncArgs.responseWriter
	request := httpFuncArgs.request
	method := request.Method
	client := request.RemoteAddr

	geoip := &GeoIP{}
	geoip.Reader, err = maxminddb.Open(config.GeoipPath)

	if err != nil {
		responseWriter.WriteHeader(http.StatusInternalServerError)
		level.Error(logger).Log(
			"guid", guid,
			"client", client,
			"request", method,
			"path", request.URL.Path,
			"error", err.Error())

		return
	}

	geoIPStore.Store(geoip)

	level.Info(logger).Log(
		"guid", guid,
		"client", client,
		"request", method,
		"path", request.URL.Path,
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
				"path", request.URL.Path,
				"file", config.CustomSettingsPath,
				"result", "reloaded")
		}
	}

	responseWriter.WriteHeader(http.StatusAccepted)
}

func httpGETCustomSettings(httpFuncArgs *HTTPFuncArgs) {
	guid := httpFuncArgs.guid
	responseWriter := httpFuncArgs.responseWriter
	request := httpFuncArgs.request
	method := request.Method
	client := request.RemoteAddr

	responseWriter.Header().Set("Content-Type", "application/json")

	//nolint:forcetypeassert // Global variable
	if customSettings := customSettingsStore.Load().(*CustomSettings); customSettings != nil {
		if err := json.NewEncoder(responseWriter).Encode(customSettings.Data); err != nil {
			level.Error(logger).Log(
				"guid", guid,
				"client", client,
				"request", method,
				"path", request.URL.Path,
				"error", err.Error())

			return
		}

		level.Info(logger).Log(
			"guid", guid, "client", client, "request", method, "path", request.URL.Path)
	} else {
		responseWriter.WriteHeader(http.StatusNoContent)

		level.Info(logger).Log(
			"guid", guid, "client", client, "request", method, "path", request.URL.Path)
	}
}
