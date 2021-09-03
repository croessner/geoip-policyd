package main

import (
	"github.com/oschwald/maxminddb-golang"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const version string = "2021.0.3"

func main() {
	var (
		err      error
		protocol = "tcp"
		server   net.Listener
	)

	initConfig(os.Args)

	log.Printf("Starting with configuration: %+v", cfg)

	if sa := net.ParseIP(cfg.ServerAddress); sa == nil {
		if _, err = net.LookupHost(cfg.ServerAddress); err != nil {
			if u := strings.Split(cfg.ServerAddress, "unix:"); len(u) == 0 {
				log.Fatalln(
					"Error: --server-address", cfg.ServerAddress, "is not a valid IP, hostname nor unix path")
			} else {
				protocol = "unix"
			}
		}
	}

	if ra := net.ParseIP(cfg.RedisAddress); ra == nil {
		if _, err = net.LookupHost(cfg.RedisAddress); err != nil {
			if u := strings.Split(cfg.RedisAddress, "unix:"); len(u) == 0 {
				log.Fatalln(
					"Error: --redis-address", cfg.RedisAddress, "is not a valid IP, hostname nor unix path")
			}
		}
	}

	geoipReader, err = maxminddb.Open(cfg.GeoipPath)
	if err != nil {
		log.Fatal("Error: Can not open GeoLite2-City database file", err)
	}

	//goland:noinspection GoUnhandledErrorResult
	defer geoipReader.Close()

	server, err = net.Listen(protocol, cfg.ServerAddress+":"+strconv.Itoa(cfg.ServerPort))
	if server == nil {
		log.Panic("Error: Unable to start server:", err)
	}
	clientChannel := clientConnections(server)
	for {
		go handleConnection(<-clientChannel)
	}
}
