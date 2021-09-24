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
	"github.com/oschwald/maxminddb-golang"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
)

const version = "@@gittag@@-@@gitcommit@@"

var (
	cfg *CmdLineConfig

	// Reloadable data
	cs atomic.Value
	gi atomic.Value
)

func initCustomSettings(cfg *CmdLineConfig) *CustomSettings {
	customSettings := new(CustomSettings)
	if cfg.CustomSettingsPath != "" {
		jsonFile, err := os.Open(cfg.CustomSettingsPath)
		if err != nil {
			log.Fatalln("Error:", err)
		}

		//goland:noinspection GoUnhandledErrorResult
		defer jsonFile.Close()

		if byteValue, err := ioutil.ReadAll(jsonFile); err != nil {
			log.Fatalln("Error:", err)
		} else {
			if err := json.Unmarshal(byteValue, customSettings); err != nil {
				log.Fatalln("Error:", err)
			}
		}
	}
	return customSettings
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
		cs.Store(initCustomSettings(cfg))

		log.Printf("Starting geoip-policyd server (%s): '%s:%d'\n", version, cfg.ServerAddress, cfg.ServerPort)

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

		geoip := new(GeoIP)
		geoip.Reader, err = maxminddb.Open(cfg.GeoipPath)
		if err != nil {
			log.Fatal("Error: Can not open GeoLite2-City database file", err)
		}
		gi.Store(geoip)

		// REST interface
		go httpApp()

		server, err = net.Listen("tcp", cfg.ServerAddress+":"+strconv.Itoa(cfg.ServerPort))
		if server == nil {
			log.Panic("Error: Unable to start server:", err)
		}
		clientChannel := clientConnections(server)
		for {
			go handleConnection(<-clientChannel, cfg)
		}
	}
}
