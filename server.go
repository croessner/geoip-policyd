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
	"log"
	"net"
	"strings"
)

func clientConnections(listener net.Listener) chan net.Conn {
	ch := make(chan net.Conn)
	go func() {
		for {
			client, err := listener.Accept()
			if client == nil {
				log.Println("Error: Couldn't accept connection:", err)
				continue
			}
			if cfg.Verbose >= logLevelInfo {
				log.Printf("Connection %v established\n", client.RemoteAddr())
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

	for {
		lineBytes, err := b.ReadBytes('\n')
		if err != nil { // EOF, or worse
			if cfg.Verbose == logLevelDebug {
				log.Printf("Connection %v disconnected\n", client.RemoteAddr())
			}
			client.Close()
			break
		}

		lineStr := strings.TrimSpace(string(lineBytes))
		items := strings.Split(lineStr, "=")
		if len(items) == 2 {
			policyRequest[strings.TrimSpace(items[0])] = strings.TrimSpace(items[1])
		} else {
			if cfg.Verbose >= logLevelInfo {
				log.Println("Debug:", policyRequest)
			}

			result := getPolicyResponse(cfg, policyRequest)
			client.Write([]byte(result + "\n\n"))
			policyRequest = make(map[string]string) // Clear policy request for next connection
		}
	}
}
