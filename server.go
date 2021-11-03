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
	"net"
	"strings"
)

func clientConnections(listener net.Listener) chan net.Conn {
	ch := make(chan net.Conn)
	go func() {
		for {
			client, err := listener.Accept()
			if client == nil {
				ErrorLogger.Println("Couldn't accept connection:", err)
				continue
			}
			if cfg.VerboseLevel == logLevelDebug {
				DebugLogger.Printf("Client %v connected\n", client.RemoteAddr())
			}
			ch <- client
		}
	}()
	return ch
}

//goland:noinspection GoUnhandledErrorResult
func handleConnection(client net.Conn, cfg *CmdLineConfig) {
	b := bufio.NewReader(client)
	var policyRequest = make(map[string]string)
	var instance string

	for {
		lineBytes, err := b.ReadBytes('\n')
		if err != nil { // EOF, or worse
			if cfg.VerboseLevel == logLevelDebug {
				DebugLogger.Printf("Client %v disconnected\n", client.RemoteAddr())
			}
			client.Close()
			break
		}

		lineStr := strings.TrimSpace(string(lineBytes))
		items := strings.SplitN(lineStr, "=", 2)
		if len(items) == 2 {
			policyRequest[strings.TrimSpace(items[0])] = strings.TrimSpace(items[1])
		} else {
			if cfg.VerboseLevel == logLevelDebug {
				if val, ok := policyRequest["instance"]; ok {
					instance = val
				} else {
					instance = "-"
				}
				DebugLogger.Printf("instance=\"%s\" %+v\n", instance, policyRequest)
			}

			result := getPolicyResponse(cfg, policyRequest)
			client.Write([]byte(result + "\n\n"))
			policyRequest = make(map[string]string) // Clear policy request for next connection
		}
	}
}
