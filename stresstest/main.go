package main

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"
)

const MaxConnections = 100
const TotalConnections = 100000

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Required args: <host:port> <sender> <client_address>")
		os.Exit(1)
	}

	counter := make(chan int, MaxConnections)
	host := os.Args[1]
	sender := os.Args[2]
	clientAddress := os.Args[3]

	msg := fmt.Sprintf("request=smtpd_access_policy\nsender=%s\nclient_address=%s\n\n", sender, clientAddress)

	for i := 0; i < TotalConnections; i++ {
		counter <- i
		go func() {
			var (
				conn   net.Conn
				err    error
				line   string
				cycles int
			)

			if conn, err = net.Dial("tcp", host); err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}

			defer func() { _ = conn.Close() }()

			_, err = conn.Write([]byte(msg))
			if err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}

			cycles = 0
			for {
				reader := bufio.NewReader(conn)
				tp := textproto.NewReader(reader)
				line, _ = tp.ReadLine()
				if strings.HasPrefix(line, "action=") {
					break
				} else {
					time.Sleep(10 * time.Millisecond)
					if cycles > 5000 {
						line = "Timeout"
						break
					}
				}
			}

			fmt.Println(<-counter, line)
		}()
	}
}
