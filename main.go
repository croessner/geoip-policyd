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
	"github.com/gomodule/redigo/redis"
	"github.com/oschwald/maxminddb-golang"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

const version = "@@gittag@@-@@gitcommit@@"

var (
	cfg   *CmdLineConfig
	wl    *WhiteList
	geoip *GeoIP
)

const (
	GET    = "GET"
	DELETE = "DELETE"
)

func httpRootPage(rw http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		log.Println("Error:", err)
		return
	}

	method := request.Method
	values := request.Form
	uri := request.URL

	switch method {
	case GET:
		switch uri.Path {
		case "/reload":
			var err error

			//goland:noinspection GoUnhandledErrorResult
			geoip.Reader.Close()
			geoip.Reader, err = maxminddb.Open(cfg.GeoipPath)
			if err != nil {
				log.Fatal("Error: Can not open GeoLite2-City database file", err)
			}
			log.Println("Reloaded GeoLite2-City database file")

			if wl != nil {
				wl.Mu.Lock()
				wl = initWhitelist(cfg)
				wl.Mu.Unlock()
				log.Println("Reloaded whitelist file")
			}

			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(rw, "OK reload")

		case "/whitelist":
			if wl == nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(rw, "[]")
				return
			}
			if jsonValue, err := json.Marshal(wl.Data); err != nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(rw, "[]")
			} else {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintf(rw, "%+v\n", string(jsonValue))
			}
		}

	case DELETE:
		switch uri.Path {
		case "/remove":
			if val, ok := values["sender"]; ok {
				sender := val[0]
				if sender == "" {
					//goland:noinspection GoUnhandledErrorResult
					fmt.Fprintln(rw, "[]")
					return
				}

				var redisHelper = &Redis{}
				redisConnW := redisHelper.WriteConn()

				//goland:noinspection GoUnhandledErrorResult
				defer redisConnW.Close()

				if cfg.UseLDAP {
					var err error
					var ldapResult string

					ldapServer := &cfg.LDAP

					if ldapResult, err = ldapServer.Search(sender); err != nil {
						log.Println("Info:", err)
						if !strings.Contains(fmt.Sprint(err), "No Such Object") {
							if ldapServer.LDAPConn == nil {
								ldapServer.Connect()
								ldapServer.Bind()
								ldapResult, _ = ldapServer.Search(sender)
							}
						}
					}
					if ldapResult != "" {
						sender = ldapResult
					}

				}

				key := fmt.Sprintf("%s%s", cfg.RedisPrefix, sender)
				if _, err := redisConnW.Do("DEL",
					redis.Args{}.Add(key)...); err != nil {
					log.Println("Error:", err)
				}
			}
		}

	default:
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func initWhitelist(cfg *CmdLineConfig) *WhiteList {
	w := new(WhiteList)
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
			if err := json.Unmarshal(byteValue, w); err != nil {
				log.Fatalln("Error:", err)
			}
		}
	}
	return w
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
		wl = initWhitelist(cfg)

		log.Printf("Starting geoip-policyd server (%s): '%s:%d'\n", version, cfg.ServerAddress, cfg.ServerPort)
		log.Printf("Starting geoip-policyd HTTP service with address: '%s'", cfg.HttpAddress)

		if cfg.Verbose == logLevelDebug {
			log.Println("Debug:", cfg)
		}

		if cfg.UseLDAP {
			ldapServer = &cfg.LDAP
			if cfg.Verbose == logLevelDebug {
				log.Println("Debug: LDAP:", ldapServer)
			}
			ldapServer.Connect()
			ldapServer.Bind()
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
