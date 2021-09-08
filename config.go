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
	"fmt"
	"github.com/akamensky/argparse"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Defaults
const (
	serverAddress = "127.0.0.1"
	serverPort    = 4646
	redisAddress  = "127.0.0.1"
	redisPort     = 6379
	geoipPath     = "/usr/share/GeoIP/GeoLite2-City.mmdb"
	redisPrefix   = "geopol_"
	redisTTL      = 3600
	maxCountries  = 3
	maxIps        = 10
	httpAddress   = ":8080"
	httpURI       = "http://127.0.0.1:8080"
)

type CmdLineConfig struct {
	ServerAddress string
	ServerPort    int
	HttpAddress   string
	HttpURI       string

	RedisAddress  string
	RedisPort     int
	RedisDB       int
	RedisUsername string
	RedisPassword string

	RedisAddressW  string
	RedisPortW     int
	RedisDBW       int
	RedisUsernameW string
	RedisPasswordW string

	RedisPrefix string
	RedisTTL    int

	GeoipPath    string
	MaxCountries int
	MaxIps       int
	Verbose      bool

	CommandServer bool
	CommandReload bool

	WhiteListPath string
	WhiteList     WhiteList
}

type WhiteList struct {
	Mu   sync.Mutex
	Data []Account `json:"data"`
}

type Account struct {
	Comment   string `json:"comment"`
	Sender    string `json:"sender"`
	Ips       int    `json:"ips"`
	Countries int    `json:"countries"`
}

func (c *CmdLineConfig) Init(args []string) {
	parser := argparse.NewParser("geoip-policyd", "Detect compromised e-mail accounts")

	commandServer := parser.NewCommand("server", "Run a geoip policy server")

	/*
	 * GeoIP policy server options
	 */
	argServerAddress := commandServer.String(
		"a", "server-address", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if addr := net.ParseIP(opt[0]); addr == nil {
					if _, err := net.LookupHost(opt[0]); err != nil {
						return fmt.Errorf("%sis not a valid IP address or hostname", opt[0])
					}
				}
				return nil
			},
			Help: "IPv4 or IPv6 address for the policy service; default(" + serverAddress + ")",
		},
	)
	argServerPort := commandServer.Int(
		"p", "server-port", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return fmt.Errorf("%s is not an integer", opt[0])
				} else {
					if !(arg > 0 && arg <= 65535) {
						return fmt.Errorf("%s is not a valid port number", opt[0])
					}
				}
				return nil
			},
			Help: "Port for the policy service; default(" + strconv.Itoa(serverPort) + ")",
		},
	)
	argServerHttpAddress := commandServer.String(
		"", "http-address", &argparse.Options{
			Required: false,
			Help:     "HTTP address for incoming requests; default(" + httpAddress + ")",
		},
	)

	/*
	 * Redis options for read and/or write requests
	 */
	argServerRedisAddress := commandServer.String(
		"A", "redis-address", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if addr := net.ParseIP(opt[0]); addr == nil {
					if _, err := net.LookupHost(opt[0]); err != nil {
						return fmt.Errorf("%sis not a valid IP address or hostname", opt[0])
					}
				}
				return nil
			},
			Help: "IPv4 or IPv6 address for the Redis service; default(" + redisAddress + ")",
		},
	)
	argServerRedisPort := commandServer.Int(
		"P", "redis-port", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return fmt.Errorf("%s is not an integer", opt[0])
				} else {
					if !(arg > 0 && arg <= 65535) {
						return fmt.Errorf("%s is not a valid port number", opt[0])
					}
				}
				return nil
			},
			Help: "Port for the Redis service; default(" + strconv.Itoa(redisPort) + ")",
		},
	)
	argServerRedisDB := commandServer.Int(
		"", "redis-database-number", &argparse.Options{
			Required: false,
			Help:     "Redis database number",
		},
	)
	argServerRedisUsername := commandServer.String(
		"", "redis-username", &argparse.Options{
			Required: false,
			Help:     "Redis username",
		},
	)
	argServerRedisPassword := commandServer.String(
		"", "redis-password", &argparse.Options{
			Required: false,
			Help:     "Redis password",
		},
	)

	/*
	 * Redis options for write requests
	 */
	argServerRedisAddressW := commandServer.String(
		"", "redis-writer-address", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if addr := net.ParseIP(opt[0]); addr == nil {
					if _, err := net.LookupHost(opt[0]); err != nil {
						return fmt.Errorf("%sis not a valid IP address or hostname", opt[0])
					}
				}
				return nil
			},
			Help: "IPv4 or IPv6 address for a Redis service (writer)",
		},
	)
	argServerRedisPortW := commandServer.Int(
		"", "redis-writer-port", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return fmt.Errorf("%s is not an integer", opt[0])
				} else {
					if !(arg > 0 && arg <= 65535) {
						return fmt.Errorf("%s is not a valid port number", opt[0])
					}
				}
				return nil
			},
			Help: "Port for a Redis service (writer)",
		},
	)
	argServerRedisDBW := commandServer.Int(
		"", "redis-writer-database-number", &argparse.Options{
			Required: false,
			Help:     "Redis database number (writer)",
		},
	)
	argServerRedisUsernameW := commandServer.String(
		"", "redis-writer-username", &argparse.Options{
			Required: false,
			Help:     "Redis username (writer)",
		},
	)
	argServerRedisPasswordW := commandServer.String(
		"", "redis-writer-password", &argparse.Options{
			Required: false,
			Help:     "Redis password (writer)",
		},
	)

	/*
	 * Common Redis options
	 */
	argServerRedisPrefix := commandServer.String(
		"", "redis-prefix", &argparse.Options{
			Required: false,
			Help:     "Redis prefix; default(" + redisPrefix + ")",
		},
	)
	argServerRedisTTL := commandServer.Int(
		"", "redis-ttl", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return fmt.Errorf("%s is not an integer", opt[0])
				} else {
					if arg < 1 {
						return fmt.Errorf("%d must be an unsigned integer and not 0", arg)
					}
				}
				return nil
			},
			Help: "Redis TTL; default(" + strconv.Itoa(redisTTL) + ")",
		},
	)

	/*
	 * Other config options
	 */
	argServerGeoIPDB := commandServer.String(
		"g", "geoip-path", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if _, err := os.Stat(opt[0]); os.IsNotExist(err) {
					return fmt.Errorf("%s: %s", opt[0], err)
				}
				return nil
			},
			Help: "Full path to the GeoIP database file; default(" + geoipPath + ")",
		},
	)
	argServerMaxCountries := commandServer.Int(
		"", "max-countries", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return fmt.Errorf("%s is not an integer", opt[0])
				} else {
					if arg < 2 {
						return fmt.Errorf("%d must be an unsigned integer and greate or equal than 2", arg)
					}
				}
				return nil
			},
			Help: "Maximum number of countries before rejecting e-mails; default(" + strconv.Itoa(maxCountries) + ")",
		},
	)
	argServerMaxIps := commandServer.Int(
		"", "max-ips", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return fmt.Errorf("%s is not an integer", opt[0])
				} else {
					if arg < 1 {
						return fmt.Errorf("%d must be an unsigned integer and not 0", arg)
					}
				}
				return nil
			},
			Help: "Maximum number of IP addresses before rejecting e-mails; default(" + strconv.Itoa(maxIps) + ")",
		},
	)
	argServerWhiteListPath := commandServer.String(
		"w", "whitelist-path", &argparse.Options{
			Required: false,
			Help:     "Whitelist with different IP and country limits",
		},
	)

	argVerbose := parser.Flag(
		"v", "verbose", &argparse.Options{
			Help: "Verbose mode",
		},
	)
	argVersion := parser.Flag(
		"", "version", &argparse.Options{
			Help: "Current version",
		},
	)

	commandReload := parser.NewCommand("reload", "Reload the geoip-policyd server")

	argReloadHttpURI := commandReload.String(
		"", "http-uri", &argparse.Options{
			Required: false,
			Help:     "HTTP URI to the REST server; default(" + httpURI + ")",
		},
	)

	err := parser.Parse(args)
	if err != nil {
		log.Fatalln(parser.Usage(err))
	}

	// Map defaults
	c.ServerAddress = serverAddress
	c.ServerPort = serverPort
	c.RedisAddress = redisAddress
	c.RedisPort = redisPort
	c.RedisAddressW = redisAddress
	c.RedisPortW = redisPort
	c.RedisPrefix = redisPrefix
	c.RedisTTL = redisTTL
	c.GeoipPath = geoipPath
	c.MaxCountries = maxCountries
	c.MaxIps = maxIps
	c.HttpAddress = httpAddress
	c.HttpURI = httpURI

	if *argVersion {
		fmt.Println("Version:", version)
		os.Exit(0)
	}

	c.Verbose = *argVerbose

	c.CommandServer = commandServer.Happened()
	c.CommandReload = commandReload.Happened()

	if commandServer.Happened() {
		if val := os.Getenv("SERVER_ADDRESS"); val != "" {
			c.ServerAddress = val
		} else {
			if *argServerAddress != "" {
				c.ServerAddress = *argServerAddress
			}
		}
		if val := os.Getenv("SERVER_PORT"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: SERVER_PORT an not be used:", parser.Usage(err))
			}
			c.ServerPort = p
		} else {
			if *argServerPort != 0 {
				c.ServerPort = *argServerPort
			}
		}
		if val := os.Getenv("SERVER_HTTP_ADDRESS"); val != "" {
			c.HttpAddress = val
		} else {
			if *argServerHttpAddress != "" {
				c.HttpAddress = *argServerHttpAddress
			}
		}

		if val := os.Getenv("REDIS_ADDRESS"); val != "" {
			c.RedisAddress = val
		} else {
			if *argServerRedisAddress != "" {
				c.RedisAddress = *argServerRedisAddress
			}
		}
		if val := os.Getenv("REDIS_PORT"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_PORT can not be used:", parser.Usage(err))
			}
			c.RedisPort = p
		} else {
			if *argServerRedisPort != 0 {
				c.RedisPort = *argServerRedisPort
			}
		}
		if val := os.Getenv("REDIS_DATABASE_NUMBER"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_DATABASE_NUMBER can not be used:", parser.Usage(err))
			}
			c.RedisDB = p
		} else {
			if *argServerRedisDB > 0 {
				c.RedisDB = *argServerRedisDB
			}
		}
		if val := os.Getenv("REDIS_USERNAME"); val != "" {
			c.RedisUsername = val
		} else {
			if *argServerRedisUsername != "" {
				c.RedisUsername = *argServerRedisUsername
			}
		}
		if val := os.Getenv("REDIS_PASSWORD"); val != "" {
			c.RedisPassword = val
		} else {
			if *argServerRedisPassword != "" {
				c.RedisPassword = *argServerRedisPassword
			}
		}

		if val := os.Getenv("REDIS_WRITER_ADDRESS"); val != "" {
			c.RedisAddressW = val
		} else {
			if *argServerRedisAddressW != "" {
				c.RedisAddressW = *argServerRedisAddressW
			}
		}
		if val := os.Getenv("REDIS_WRITER_PORT"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_WRITER_PORT can not be used:", parser.Usage(err))
			}
			c.RedisPortW = p
		} else {
			if *argServerRedisPortW != 0 {
				c.RedisPortW = *argServerRedisPortW
			}
		}
		if val := os.Getenv("REDIS_WRITER_DATABASE_NUMBER"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_WRITER_DATABASE_NUMBER can not be used:", parser.Usage(err))
			}
			c.RedisDBW = p
		} else {
			if *argServerRedisDBW > 0 {
				c.RedisDBW = *argServerRedisDBW
			}
		}
		if val := os.Getenv("REDIS_WRITER_USERNAME"); val != "" {
			c.RedisUsernameW = val
		} else {
			if *argServerRedisUsernameW != "" {
				c.RedisUsernameW = *argServerRedisUsernameW
			}
		}
		if val := os.Getenv("REDIS_WRITER_PASSWORD"); val != "" {
			c.RedisPasswordW = val
		} else {
			if *argServerRedisPasswordW != "" {
				c.RedisPasswordW = *argServerRedisPasswordW
			}
		}

		if val := os.Getenv("REDIS_PREFIX"); val != "" {
			c.RedisPrefix = val
		} else {
			if *argServerRedisPrefix != "" {
				c.RedisPrefix = *argServerRedisPrefix
			}
		}
		if val := os.Getenv("REDIS_TTL"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_TTL can not be used:", parser.Usage(err))
			}
			c.RedisTTL = p
		} else {
			if *argServerRedisTTL != 0 {
				c.RedisTTL = *argServerRedisTTL
			}
		}

		if val := os.Getenv("GEOIP_PATH"); val != "" {
			c.GeoipPath = val
		} else {
			if *argServerGeoIPDB != "" {
				c.GeoipPath = *argServerGeoIPDB
			}
		}

		if val := os.Getenv("MAX_COUNTRIES"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: MAX_COUNTRIES can not be used:", parser.Usage(err))
			}
			c.MaxCountries = p
		} else {
			if *argServerMaxCountries != 0 {
				c.MaxCountries = *argServerMaxCountries
			}
		}
		if val := os.Getenv("MAX_IPS"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: MAX_IPS can not be used:", parser.Usage(err))
			}
			c.MaxIps = p
		} else {
			if *argServerMaxIps != 0 {
				c.MaxIps = *argServerMaxIps
			}
		}

		if val := os.Getenv("WHITELIST_PATH"); val != "" {
			c.WhiteListPath = val
		} else {
			if *argServerWhiteListPath != "" {
				c.WhiteListPath = *argServerWhiteListPath
			}
		}
	}

	if commandReload.Happened() {
		if val := os.Getenv("RELOAD_HTTP_URI"); val != "" {
			c.HttpURI = val
		} else {
			if *argReloadHttpURI != "" {
				c.HttpURI = *argReloadHttpURI
			}
		}
		if strings.HasSuffix(c.HttpURI, "/") {
			c.HttpURI = c.HttpURI[:len(c.HttpURI)-1]
		}
	}
}
