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
	"encoding/json"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

const version string = "@@gittag@@-@@gitcommit@@"

var (
	cfg   *CmdLineConfig
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

		if r.RequestURI == "/whitelist" {
			if jsonValue, err := json.Marshal(cfg.WhiteList.Data); err != nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(w, "[]")
			} else {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintf(w, "%+v\n", string(jsonValue))
			}
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
		err        error
		server     net.Listener
		ldapServer *LDAP
	)

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	cfg = new(CmdLineConfig)
	cfg.Init(os.Args)

	go func() {
		sig := <-sigs
		log.Println("Shutting down. Received signal:", sig)
		os.Exit(0)
	}()

	if cfg.CommandServer {
		initWhitelist(cfg)

		log.Printf("Starting geoip-policyd server (%s): '%s:%d'\n", version, cfg.ServerAddress, cfg.ServerPort)
		log.Printf("Starting geoip-policyd HTTP service with address: '%s'", cfg.HttpAddress)

		if cfg.UseLDAP {
			ldapServer = &cfg.LDAP
			ldapServer.Connect()
			ldapServer.Bind()
		}
		if cfg.Verbose == logLevelDebug {
			log.Printf("Debug: Configuration: %+v", cfg)
		}

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

	if cfg.CommandStats {
		if cfg.CommandStatsOption.printWhitelist {
			resp, err := http.Get(fmt.Sprintf("%s%s", cfg.HttpURI, "/whitelist"))
			if err != nil {
				fmt.Println("Error", err)
				os.Exit(1)
			}
			//goland:noinspection GoUnhandledErrorResult
			io.Copy(os.Stdout, resp.Body)
		}
	}
}
