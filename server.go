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
	"bufio"
	"fmt"
	"net"
	"strings"

	"github.com/go-kit/log/level"
	"github.com/segmentio/ksuid"
)

func clientConnections(listener net.Listener) chan net.Conn {
	clientConnectionsChan := make(chan net.Conn)

	go func() {
		for {
			client, err := listener.Accept()
			if client == nil {
				level.Error(logger).Log("error", err.Error())

				continue
			}

			level.Debug(logger).Log("msg", "Client connected", "client_ip", client.RemoteAddr().String())

			clientConnectionsChan <- client
		}
	}()

	return clientConnectionsChan
}

//goland:noinspection GoUnhandledErrorResult
func handleConnection(client net.Conn) {
	b := bufio.NewReader(client)
	policyRequest := make(map[string]string)

	for {
		lineBytes, err := b.ReadBytes('\n')
		if err != nil { // EOF, or worse
			level.Debug(logger).Log("msg", "Client disconnected", "client_ip", client.RemoteAddr().String())
			client.Close()

			break
		}

		lineStr := strings.TrimSpace(string(lineBytes))
		//nolint:gomnd // Split into key and "list" of values
		items := strings.SplitN(lineStr, "=", 2)

		//nolint:gomnd // Either items is a key=value pair or it is empty, indicating the end of the request
		if len(items) == 2 {
			policyRequest[strings.TrimSpace(items[0])] = strings.TrimSpace(items[1])
		} else {
			var (
				prefix         string
				actionText     string
				policyResponse *PolicyResponse
			)

			policyResponse, err = getPolicyResponse(policyRequest, ksuid.New().String())

			if err != nil {
				prefix = "DEFER "
				actionText = deferText

				level.Error(logger).Log("error", err.Error())
			} else {
				if policyResponse.fired {
					prefix = "REJECT "
					actionText = rejectText
				} else {
					if policyResponse.whitelisted {
						prefix = "INFO "
						actionText = fmt.Sprintf("Client IP address <%s> is defined in ignore-networks", policyRequest["client_address"])
					} else {
						prefix = "DUNNO"
					}
				}
			}

			client.Write([]byte(fmt.Sprintf("action=%s%s\n\n", prefix, actionText)))

			// Clear policy request for next connection
			policyRequest = make(map[string]string)
		}
	}
}
