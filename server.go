package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func clientConnections(listener net.Listener) chan net.Conn {
	ch := make(chan net.Conn)
	go func() {
		for {
			client, err := listener.Accept()
			if client == nil {
				fmt.Println("Error: Couldn't accept connection:", err)
				continue
			}
			fmt.Printf("Connection from %v established\n", client.RemoteAddr())
			ch <- client
		}
	}()
	return ch
}

//goland:noinspection GoUnhandledErrorResult
func handleConnection(client net.Conn) {
	b := bufio.NewReader(client)
	policyRequest = make(map[string]string)

	for {
		lineBytes, err := b.ReadBytes('\n')
		if err != nil { // EOF, or worse
			client.Close()
			break
		}

		lineStr := strings.TrimSpace(string(lineBytes))
		items := strings.Split(lineStr, "=")
		if len(items) == 2 {
			policyRequest[strings.TrimSpace(items[0])] = strings.TrimSpace(items[1])
		} else {
			if cfg.verbose {
				fmt.Println("Debug:", policyRequest)
			}

			result := getPolicyResponse()
			client.Write([]byte(result + "\n\n"))
			policyRequest = make(map[string]string) // Clear policy request for next connection
		}
	}
}
