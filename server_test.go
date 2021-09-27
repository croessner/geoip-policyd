package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestServerSimple(t *testing.T) {
	var server net.Listener
	var err error
	var tcpAddress *net.TCPAddr
	var clientConn *net.TCPConn

	_ = os.Setenv("GO_TESTING", "1")

	cfg = new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--server-address", "127.0.0.1", "--server-port", "53921"})

	server, err = net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.ServerAddress, cfg.ServerPort))
	if server == nil {
		t.Errorf("Unable to start server: %s", err)
	}
	clientChannel := clientConnections(server)

	tcpAddress, err = net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", cfg.ServerAddress, cfg.ServerPort))
	if err != nil {
		t.Errorf("ResolveTCPAddr failed: %s", err)
	}

	clientConn, err = net.DialTCP("tcp", nil, tcpAddress)
	if err != nil {
		t.Errorf("Dial failed: %s", err)
	}

	go handleConnection(<-clientChannel, cfg)

	_, err = clientConn.Write([]byte("request=smtpd_access_policy\nsender=test@example.com\nclient_address=127.0.0.1\n\n"))
	if err != nil {
		t.Errorf("Write to server failed: %s", err)
	}

	reply := make([]byte, 1024)

	_, err = clientConn.Read(reply)
	if err != nil {
		t.Errorf("Read from server failed: %s", err)
	}

	actionSlice := strings.Split(string(reply), "\n")

	if !(actionSlice[0] == "action=DEFER Service temporarily not available" || actionSlice[0] == "action=DUNNO") {
		t.Errorf("Expected action=..., got value %v\n", actionSlice[0])
	}
}
