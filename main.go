package main

import (
	"github.com/oschwald/maxminddb-golang"
	"log"
	"net"
	"os"
	"strconv"
)

const version string = "2021.0.7"

func main() {
	var (
		err    error
		server net.Listener
	)

	initConfig(os.Args)

	log.Printf("Starting with configuration: %+v", cfg)

	geoipReader, err = maxminddb.Open(cfg.GeoipPath)
	if err != nil {
		log.Fatal("Error: Can not open GeoLite2-City database file", err)
	}

	//goland:noinspection GoUnhandledErrorResult
	defer geoipReader.Close()

	server, err = net.Listen("tcp", cfg.ServerAddress+":"+strconv.Itoa(cfg.ServerPort))
	if server == nil {
		log.Panic("Error: Unable to start server:", err)
	}
	clientChannel := clientConnections(server)
	for {
		go handleConnection(<-clientChannel)
	}
}
