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
	"fmt"
	"github.com/go-kit/log/level"
	"io"
	"net/http"
)

func httpPOSTRemove(httpFuncArgs *HTTPFuncArgs) {
	var requestData *Body

	guid := httpFuncArgs.guid
	responseWriter := httpFuncArgs.responseWriter
	request := httpFuncArgs.request
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

		return
	}

	requestData = &Body{}
	if err := json.Unmarshal(body, requestData); err != nil {
		responseWriter.WriteHeader(http.StatusBadRequest)
		level.Error(logger).Log(
			"guid", guid, "client", client, "request", method, "path", request.URL.Path, "error", err.Error())

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
			"path", request.URL.Path,
			"sender", sender,
			"result", "unlocked")

		responseWriter.WriteHeader(http.StatusAccepted)
	} else {
		responseWriter.WriteHeader(http.StatusBadRequest)
		level.Error(logger).Log(
			"guid", guid, "client", client, "request", method, "path", request.URL.Path, "error", "unknown key")
	}
}

func httpPOSTQuery(httpFuncArgs *HTTPFuncArgs) {
	var (
		requestData  *Body
		policyResult string
		result       bool
	)

	guid := httpFuncArgs.guid
	responseWriter := httpFuncArgs.responseWriter
	request := httpFuncArgs.request
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

		return
	}

	requestData = &Body{}
	if err := json.Unmarshal(body, requestData); err != nil {
		responseWriter.WriteHeader(http.StatusBadRequest)
		level.Error(logger).Log(
			"guid", guid, "client", client, "request", method, "path", request.URL.Path, "error", err.Error())

		return
	}

	if requestData.Key == Client {
		clientRequest, ok := requestData.Value.(map[string]any)
		if !ok {
			responseWriter.WriteHeader(http.StatusBadRequest)
			level.Error(logger).Log(
				"guid", guid,
				"client", client,
				"request", method,
				"path", request.URL.Path,
				"error", "wrong value format",
				"value", fmt.Sprintf("%+v", requestData.Value),
				"value_type", fmt.Sprintf("%T", requestData.Value))

			return
		}

		userAttribute := "sender"
		if config.UseSASLUsername {
			userAttribute = "sasl_username"
		}

		requiredFieldsFound := false

		if _, addressFound := clientRequest["address"].(string); addressFound {
			if _, senderFound := clientRequest["sender"]; senderFound {
				requiredFieldsFound = true

				policyRequest := map[string]string{
					"request":        "smtpd_access_policy",
					"client_address": clientRequest["address"].(string),
					userAttribute:    clientRequest["sender"].(string),
				}

				policyResult = getPolicyResponse(config, policyRequest, guid)
			}
		}

		if !requiredFieldsFound {
			responseWriter.WriteHeader(http.StatusBadRequest)
			level.Error(logger).Log(
				"guid", guid,
				"client", client,
				"request", method,
				"path", request.URL.Path,
				"error", "value does not contain 'address' and 'sender' fields",
				"value", fmt.Sprintf("%+v", requestData.Value),
				"value_type", fmt.Sprintf("%T", requestData.Value))

			return
		}
	}

	if policyResult != "action=DUNNO" {
		result = false
	} else {
		result = true
	}

	respone, _ := json.Marshal(&RESTResult{
		GUID:      guid,
		Object:    Client,
		Operation: "query",
		Result:    result,
	})

	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(http.StatusAccepted)
	responseWriter.Write(respone)
}
