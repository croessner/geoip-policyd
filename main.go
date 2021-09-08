package main

import (
	"encoding/json"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

const version string = "2021.0.9"

var (
	cfg *CmdLineConfig
	geoip *GeoIP
)

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

			if cfg.WhiteListPath != "" {
				initWhitelist(cfg)
				log.Println("Reloaded whitelist file")
			}

			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(w, "OK reload")
		}
	}
}

func initWhitelist(cfg *CmdLineConfig) {
	if cfg.WhiteListPath != "" {
		jsonFile, err := os.Open(cfg.WhiteListPath)
		if err != nil {
			log.Fatalln("Error:", err)
		}

		//goland:noinspection GoUnhandledErrorResult
		defer jsonFile.Close()

		if byteValue, err := ioutil.ReadAll(jsonFile); err != nil {
			log.Fatalln("Error:", err)
		} else {
			cfg.WhiteList.Mu.Lock()
			if err := json.Unmarshal(byteValue, &cfg.WhiteList); err != nil {
				log.Fatalln("Error:", err)
			}
			cfg.WhiteList.Mu.Unlock()
		}
	}
}

func main() {
	var (
		err    error
		server net.Listener
	)

	cfg = new(CmdLineConfig)
	cfg.Init(os.Args)

	if cfg.CommandServer {
		initWhitelist(cfg)

		log.Printf("Starting with configuration: %+v", cfg)

		geoip = new(GeoIP)
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
			go handleConnection(<-clientChannel, cfg)
		}
	}

	if cfg.CommandReload {
		resp, err := http.Get(fmt.Sprintf("%s%s", cfg.HttpURI, "/reload"))
		if err != nil {
			fmt.Println("Error", err)
			os.Exit(1)
		}
		fmt.Printf("Reload-status: %s\n", resp.Status)
	}
}
