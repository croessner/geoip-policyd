// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/go-kit/log/level"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func clientConnections(listener net.Listener) chan net.Conn {
	clientConnectionsChan := make(chan net.Conn)

	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				if obs := currentObservability(); obs != nil {
					obs.ObserveTCPConnection(context.Background(), eventAccept, resultError, 0)
				}

				_ = level.Error(logger).Log("error", err.Error())

				continue
			}

			if client == nil {
				continue
			}

			if obs := currentObservability(); obs != nil {
				obs.ObserveTCPConnection(context.Background(), eventAccept, resultOK, 1)
			}

			_ = level.Debug(logger).Log("msg", "Client connected", "client_ip", client.RemoteAddr().String())

			clientConnectionsChan <- client
		}
	}()

	return clientConnectionsChan
}

//goland:noinspection GoUnhandledErrorResult
func handleConnection(client net.Conn) {
	defer func() {
		if obs := currentObservability(); obs != nil {
			obs.ObserveTCPConnection(context.Background(), eventClose, resultOK, -1)
		}
	}()

	b := bufio.NewReader(client)
	policyRequest := make(map[string]string)

	for {
		lineBytes, err := b.ReadBytes('\n')
		if err != nil { // EOF, or worse
			_ = level.Debug(logger).Log("msg", "Client disconnected", "client_ip", client.RemoteAddr().String())
			_ = client.Close()

			break
		}

		lineStr := strings.TrimSpace(string(lineBytes))
		items := strings.SplitN(lineStr, "=", 2)

		if len(items) == 2 {
			policyRequest[strings.TrimSpace(items[0])] = strings.TrimSpace(items[1])
		} else {
			prefix, actionText := handlePostfixPolicyRequest(client, policyRequest)

			if _, writeErr := client.Write(fmt.Appendf(nil, "action=%s%s\n\n", prefix, actionText)); writeErr != nil {
				_ = level.Error(logger).Log("error", writeErr.Error())
			}

			// Clear policy request for next connection
			policyRequest = make(map[string]string)
		}
	}
}

// handlePostfixPolicyRequest evaluates one complete Postfix policy request and returns the wire action fields.
func handlePostfixPolicyRequest(client net.Conn, policyRequest map[string]string) (string, string) {
	requestCtx, requestSpan, obs := startPostfixPolicyRequestSpan(client)
	defer func() {
		if requestSpan != nil {
			requestSpan.End()
		}
	}()

	policyResponse, err := getObservedPolicyResponse(requestCtx, sourcePostfixTCP, policyRequest, ksuid.New().String(), false)
	if err != nil {
		if obs != nil {
			obs.RecordSpanError(requestSpan, err)
		}

		_ = level.Error(logger).Log("error", err.Error())

		return "DEFER ", deferText
	}

	return postfixPolicyAction(policyRequest, policyResponse)
}

// startPostfixPolicyRequestSpan creates the root server span for one raw Postfix TCP policy request.
func startPostfixPolicyRequestSpan(client net.Conn) (context.Context, trace.Span, *Observability) {
	requestCtx := context.Background()

	obs := currentObservability()
	if obs == nil {
		return requestCtx, nil, nil
	}

	requestCtx, requestSpan := obs.StartSpanWithKind(
		requestCtx,
		"postfix.policy.request",
		trace.SpanKindServer,
		attribute.String("network.peer.address", client.RemoteAddr().String()),
		attribute.String("policy.source", sourcePostfixTCP),
	)

	return requestCtx, requestSpan, obs
}

// postfixPolicyAction maps an evaluated policy response to the Postfix action prefix and text.
func postfixPolicyAction(policyRequest map[string]string, policyResponse *PolicyResponse) (string, string) {
	if policyResponse.fired {
		return "REJECT ", rejectText
	}

	if policyResponse.whitelisted {
		return "INFO ", fmt.Sprintf("Client IP address <%s> is defined in ignore-networks", policyRequest[ClientAddress])
	}

	return "DUNNO", ""
}
