package main

import (
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

const version string = "2021.0.8.2"

func httpRootPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if r.RequestURI == "/reload" {
			var err error

			geoip.Mu.Lock()
			//goland:noinspection GoUnhandledErrorResult
			geoip.Reader.Close()
			geoip.Reader, err = maxminddb.Open(cfg.GeoipPath)
			geoip.Mu.Unlock()
			if err != nil {
				log.Fatal("Error: Can not open GeoLite2-City database file", err)
			}
			log.Println("Reloaded GeoLite2-City database file")

			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(w, "OK reload")
		}
	}
}

func main() {
	var (
		err    error
		server net.Listener
	)

	initConfig(os.Args)

	if cfg.CommandServer {
		log.Printf("Starting with configuration: %+v", cfg)

		geoip.Mu.Lock()
		geoip.Reader, err = maxminddb.Open(cfg.GeoipPath)
		geoip.Mu.Unlock()
		if err != nil {
			log.Fatal("Error: Can not open GeoLite2-City database file", err)
		}

		//goland:noinspection GoUnhandledErrorResult
		defer geoip.Reader.Close()

		go func() {
			http.HandleFunc("/", httpRootPage)
			log.Fatal(http.ListenAndServe(cfg.HttpAddress, nil))
		}()

		server, err = net.Listen("tcp", cfg.ServerAddress+":"+strconv.Itoa(cfg.ServerPort))
		if server == nil {
			log.Panic("Error: Unable to start server:", err)
		}
		clientChannel := clientConnections(server)
		for {
			go handleConnection(<-clientChannel)
		}
	}

	if cfg.CommandReload {
		resp, err := http.Get(fmt.Sprintf("%s%s", cfg.HttpURI, "/reload"))
		if err != nil {
			fmt.Println("Error", err)
		}
		fmt.Printf("Reload-status: %s\n", resp.Status)
	}
}
