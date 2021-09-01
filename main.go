package main

import (
	"github.com/oschwald/maxminddb-golang"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const version string = "2021.0.2"

func main() {
	var (
		err      error
		protocol = "tcp"
		server   net.Listener
	)

	initConfig(os.Args)

	if sa := net.ParseIP(cfg.serverAddress); sa == nil {
		if _, err = net.LookupHost(cfg.serverAddress); err != nil {
			if u := strings.Split(cfg.serverAddress, "unix:"); len(u) == 0 {
				log.Fatalln(
					"Error: --server-address", cfg.serverAddress, "is not a valid IP, hostname nor unix path")
			} else {
				protocol = "unix"
			}
		}
	}
	if !(cfg.serverPort > 0 && cfg.serverPort <= 65535) {
		log.Fatalln("Error: --server-port is not a valid port number:", cfg.serverPort)
	}

	if ra := net.ParseIP(cfg.redisAddress); ra == nil {
		if _, err = net.LookupHost(cfg.redisAddress); err != nil {
			if u := strings.Split(cfg.redisAddress, "unix:"); len(u) == 0 {
				log.Fatalln(
					"Error: --redis-address", cfg.redisAddress, "is not a valid IP, hostname nor unix path")
			}
		}
	}
	if !(cfg.redisPort > 0 && cfg.redisPort <= 65535) {
		log.Fatalln("Error: --redis-port is not a valid port number:", cfg.redisPort)
	}

	if _, err = os.Stat(cfg.geoipPath); os.IsNotExist(err) {
		log.Fatalln("Error:", cfg.geoipPath, "can not be read:", err)
	}

	geoipReader, err = maxminddb.Open(cfg.geoipPath)
	if err != nil {
		log.Fatal("Error: Can not open GeoLite2-City database file", err)
	}

	//goland:noinspection GoUnhandledErrorResult
	defer geoipReader.Close()

	server, err = net.Listen(protocol, cfg.serverAddress+":"+strconv.Itoa(cfg.serverPort))
	if server == nil {
		log.Panic("Error: Unable to start server:", err)
	}
	clientChannel := clientConnections(server)
	for {
		go handleConnection(<-clientChannel)
	}
}
