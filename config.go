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
	"github.com/go-ldap/ldap/v3"
	"log"
	"net"
	"os"
	"reflect"
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
	maxRetries    = 9
)

const (
	logLevelNone  = iota
	logLevelInfo  = iota
	logLevelDebug = iota
)

type CommandStatsOption struct {
	printWhitelist bool
}

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
	Verbose      int

	CommandServer bool
	CommandReload bool
	CommandStats  bool
	CommandStatsOption

	UseLDAP bool
	LDAP

	WhiteListPath string
	WhiteList
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

func (c *CmdLineConfig) String() string {
	var result string

	v := reflect.ValueOf(*c)
	typeOfc := v.Type()

	for i := 0; i < v.NumField(); i++ {
		switch typeOfc.Field(i).Name {
		case "CommandServer", "CommandReload", "CommandStats", "CommandStatsOption", "UseLDAP", "LDAP", "WhiteList", "Verbose":
			continue
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfc.Field(i).Name, v.Field(i).Interface())
		}
	}

	return result[1:]
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
			Default:  serverAddress,
			Validate: func(opt []string) error {
				if addr := net.ParseIP(opt[0]); addr == nil {
					if _, err := net.LookupHost(opt[0]); err != nil {
						return fmt.Errorf("%sis not a valid IP address or hostname", opt[0])
					}
				}
				return nil
			},
			Help: "IPv4 or IPv6 address for the policy service",
		},
	)
	argServerPort := commandServer.Int(
		"p", "server-port", &argparse.Options{
			Required: false,
			Default:  serverPort,
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
			Help: "Port for the policy service",
		},
	)
	argServerHttpAddress := commandServer.String(
		"", "http-address", &argparse.Options{
			Required: false,
			Default:  httpAddress,
			Help:     "HTTP address for incoming requests",
		},
	)

	/*
	 * Redis options for read and/or write requests
	 */
	argServerRedisAddress := commandServer.String(
		"A", "redis-address", &argparse.Options{
			Required: false,
			Default:  redisAddress,
			Validate: func(opt []string) error {
				if addr := net.ParseIP(opt[0]); addr == nil {
					if _, err := net.LookupHost(opt[0]); err != nil {
						return fmt.Errorf("%sis not a valid IP address or hostname", opt[0])
					}
				}
				return nil
			},
			Help: "IPv4 or IPv6 address for the Redis service",
		},
	)
	argServerRedisPort := commandServer.Int(
		"P", "redis-port", &argparse.Options{
			Required: false,
			Default:  redisPort,
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
			Help: "Port for the Redis service",
		},
	)
	argServerRedisDB := commandServer.Int(
		"", "redis-database-number", &argparse.Options{
			Required: false,
			Default:  0,
			Help:     "Redis database number",
		},
	)
	argServerRedisUsername := commandServer.String(
		"", "redis-username", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis username",
		},
	)
	argServerRedisPassword := commandServer.String(
		"", "redis-password", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis password",
		},
	)

	/*
	 * Redis options for write requests
	 */
	argServerRedisAddressW := commandServer.String(
		"", "redis-writer-address", &argparse.Options{
			Required: false,
			Default:  redisAddress,
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
			Default:  redisPort,
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
			Default:  0,
			Help:     "Redis database number (writer)",
		},
	)
	argServerRedisUsernameW := commandServer.String(
		"", "redis-writer-username", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis username (writer)",
		},
	)
	argServerRedisPasswordW := commandServer.String(
		"", "redis-writer-password", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis password (writer)",
		},
	)

	/*
	 * Common Redis options
	 */
	argServerRedisPrefix := commandServer.String(
		"", "redis-prefix", &argparse.Options{
			Required: false,
			Default:  redisPrefix,
			Help:     "Redis prefix",
		},
	)
	argServerRedisTTL := commandServer.Int(
		"", "redis-ttl", &argparse.Options{
			Required: false,
			Default:  redisTTL,
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
			Help: "Redis TTL in seconds",
		},
	)

	/*
	 * Other config options
	 */
	argServerGeoIPDB := commandServer.String(
		"g", "geoip-path", &argparse.Options{
			Required: false,
			Default:  geoipPath,
			Validate: func(opt []string) error {
				if _, err := os.Stat(opt[0]); os.IsNotExist(err) {
					return fmt.Errorf("%s: %s", opt[0], err)
				}
				return nil
			},
			Help: "Full path to the GeoIP database file",
		},
	)
	argServerMaxCountries := commandServer.Int(
		"", "max-countries", &argparse.Options{
			Required: false,
			Default:  maxCountries,
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
			Help: "Maximum number of countries before rejecting e-mails",
		},
	)
	argServerMaxIps := commandServer.Int(
		"", "max-ips", &argparse.Options{
			Required: false,
			Default:  maxIps,
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
			Help: "Maximum number of IP addresses before rejecting e-mails",
		},
	)
	argServerWhiteListPath := commandServer.String(
		"w", "whitelist-path", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Whitelist with different IP and country limits",
		},
	)
	argServerUseLDAP := commandServer.Flag(
		"", "use-ldap", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Enable LDAP support",
		},
	)
	argServerLDAPServerURIs := commandServer.StringList(
		"", "ldap-server-uri", &argparse.Options{
			Required: false,
			Default:  []string{"ldap://127.0.0.1:389/"},
			Help:     "Server URI. Specify multiple times, if you need more than one server",
		},
	)
	argServerLDAPBaseDN := commandServer.String(
		"", "ldap-basedn", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Base DN",
		},
	)
	argServerLDAPBindDN := commandServer.String(
		"", "ldap-binddn", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Bind DN",
		},
	)
	argServerLDAPBindPWPATH := commandServer.String(
		"", "ldap-bindpw-path", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "File containing the LDAP users password",
		},
	)
	argServerLDAPFilter := commandServer.String(
		"", "ldap-filter", &argparse.Options{
			Required: false,
			Default:  "(&(objectClass=*)(mailAlias=%s))",
			Help:     "Filter with %s placeholder",
		},
	)
	argServerLDAPResultAttr := commandServer.String(
		"", "ldap-result-attribute", &argparse.Options{
			Required: false,
			Default:  "mailAccount",
			Help:     "Result attribute for the requested mail sender",
		},
	)
	argServerLDAPStartTLS := commandServer.Flag(
		"", "ldap-starttls", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "If this option is given, use StartTLS",
		},
	)
	argServerLDAPTLSVerify := commandServer.Flag(
		"", "ldap-skip-tls-verify", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Skip TLS server name verification",
		},
	)
	argServerLDAPTLSCAFile := commandServer.String(
		"", "ldap-tls-cafile", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "File containing TLS CA certificate(s)",
		},
	)
	argServerLDAPTLSClientCert := commandServer.String(
		"", "ldap-tls-client-cert", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "File containing a TLS client certificate",
		},
	)
	argServerLDAPTLSClientKey := commandServer.String(
		"", "ldap-tls-client-key", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "File containing a TLS client key",
		},
	)
	argServerLDAPSASLExternal := commandServer.Flag(
		"", "ldap-sasl-external", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Use SASL/EXTERNAL instead of a simple bind",
		},
	)
	argServerLDAPScope := commandServer.String(
		"", "ldap-scope", &argparse.Options{
			Required: false,
			Default:  "sub",
			Validate: func(opt []string) error {
				switch opt[0] {
				case "base", "one", "sub":
					return nil
				default:
					return fmt.Errorf("value '%s' must be one of: 'one', 'base' or 'sub'", opt[0])
				}
			},
			Help: "LDAP search scope [base, one, sub]",
		},
	)

	argVerbose := parser.FlagCounter(
		"v", "verbose", &argparse.Options{
			Help: "Verbose mode. Repeat this for an increased log level",
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

	commandStats := parser.NewCommand("stats", "Get statistics from geoip-policyd server")

	argStatsPrintWhitelist := commandStats.Flag(
		"", "print-whitelist", &argparse.Options{
			Required: false,
			Help:     "Print out the currently loaded whitelist (JSON-format)",
		},
	)
	argStatsHttpURI := commandStats.String(
		"", "http-uri", &argparse.Options{
			Required: false,
			Help:     "HTTP URI to the REST server; default(" + httpURI + ")",
		},
	)

	err := parser.Parse(args)
	if err != nil {
		log.Fatalln(parser.Usage(err))
	}

	if *argVersion {
		fmt.Println("Version:", version)
		os.Exit(0)
	}

	if val := os.Getenv("VERBOSE"); val != "" {
		switch val {
		case "none":
			c.Verbose = logLevelNone
		case "info":
			c.Verbose = logLevelInfo
		case "debug":
			c.Verbose = logLevelDebug
		}
	} else {
		switch *argVerbose {
		case logLevelNone:
			c.Verbose = logLevelNone
		case logLevelInfo:
			c.Verbose = logLevelInfo
		case logLevelDebug:
			c.Verbose = logLevelDebug
		default:
			c.Verbose = logLevelDebug
		}
	}

	c.CommandServer = commandServer.Happened()
	c.CommandReload = commandReload.Happened()
	c.CommandStats = commandStats.Happened()

	if commandServer.Happened() {
		if val := os.Getenv("SERVER_ADDRESS"); val != "" {
			c.ServerAddress = val
		} else {
			c.ServerAddress = *argServerAddress
		}
		if val := os.Getenv("SERVER_PORT"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: SERVER_PORT an not be used:", parser.Usage(err))
			}
			c.ServerPort = p
		} else {
			c.ServerPort = *argServerPort
		}
		if val := os.Getenv("SERVER_HTTP_ADDRESS"); val != "" {
			c.HttpAddress = val
		} else {
			c.HttpAddress = *argServerHttpAddress
		}

		if val := os.Getenv("REDIS_ADDRESS"); val != "" {
			c.RedisAddress = val
		} else {
			c.RedisAddress = *argServerRedisAddress
		}
		if val := os.Getenv("REDIS_PORT"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_PORT can not be used:", parser.Usage(err))
			}
			c.RedisPort = p
		} else {
			c.RedisPort = *argServerRedisPort
		}
		if val := os.Getenv("REDIS_DATABASE_NUMBER"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_DATABASE_NUMBER can not be used:", parser.Usage(err))
			}
			c.RedisDB = p
		} else {
			c.RedisDB = *argServerRedisDB
		}
		if val := os.Getenv("REDIS_USERNAME"); val != "" {
			c.RedisUsername = val
		} else {
			c.RedisUsername = *argServerRedisUsername
		}
		if val := os.Getenv("REDIS_PASSWORD"); val != "" {
			c.RedisPassword = val
		} else {
			c.RedisPassword = *argServerRedisPassword
		}

		if val := os.Getenv("REDIS_WRITER_ADDRESS"); val != "" {
			c.RedisAddressW = val
		} else {
			c.RedisAddressW = *argServerRedisAddressW
		}
		if val := os.Getenv("REDIS_WRITER_PORT"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_WRITER_PORT can not be used:", parser.Usage(err))
			}
			c.RedisPortW = p
		} else {
			c.RedisPortW = *argServerRedisPortW
		}
		if val := os.Getenv("REDIS_WRITER_DATABASE_NUMBER"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_WRITER_DATABASE_NUMBER can not be used:", parser.Usage(err))
			}
			c.RedisDBW = p
		} else {
			c.RedisDBW = *argServerRedisDBW
		}
		if val := os.Getenv("REDIS_WRITER_USERNAME"); val != "" {
			c.RedisUsernameW = val
		} else {
			c.RedisUsernameW = *argServerRedisUsernameW
		}
		if val := os.Getenv("REDIS_WRITER_PASSWORD"); val != "" {
			c.RedisPasswordW = val
		} else {
			c.RedisPasswordW = *argServerRedisPasswordW
		}

		if val := os.Getenv("REDIS_PREFIX"); val != "" {
			c.RedisPrefix = val
		} else {
			c.RedisPrefix = *argServerRedisPrefix
		}
		if val := os.Getenv("REDIS_TTL"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: REDIS_TTL can not be used:", parser.Usage(err))
			}
			c.RedisTTL = p
		} else {
			c.RedisTTL = *argServerRedisTTL
		}

		if val := os.Getenv("GEOIP_PATH"); val != "" {
			c.GeoipPath = val
		} else {
			c.GeoipPath = *argServerGeoIPDB
		}

		if val := os.Getenv("MAX_COUNTRIES"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: MAX_COUNTRIES can not be used:", parser.Usage(err))
			}
			c.MaxCountries = p
		} else {
			c.MaxCountries = *argServerMaxCountries
		}
		if val := os.Getenv("MAX_IPS"); val != "" {
			p, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: MAX_IPS can not be used:", parser.Usage(err))
			}
			c.MaxIps = p
		} else {
			c.MaxIps = *argServerMaxIps
		}

		if val := os.Getenv("WHITELIST_PATH"); val != "" {
			c.WhiteListPath = val
		} else {
			c.WhiteListPath = *argServerWhiteListPath
		}

		if val := os.Getenv("USE_LDAP"); val != "" {
			p, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err)
			}
			c.UseLDAP = p
		} else {
			c.UseLDAP = *argServerUseLDAP
		}

		if c.UseLDAP {
			if val := os.Getenv("LDAP_SERVER_URIS"); val != "" {
				p := strings.Split(val, ",")
				for i, uri := range p {
					p[i] = strings.TrimSpace(uri)
				}
				c.LDAP.ServerURIs = p
			} else {
				c.LDAP.ServerURIs = *argServerLDAPServerURIs
			}
			if val := os.Getenv("LDAP_BASEDN"); val != "" {
				c.LDAP.BaseDN = val
			} else {
				c.LDAP.BaseDN = *argServerLDAPBaseDN
			}
			if val := os.Getenv("LDAP_BINDDN"); val != "" {
				c.LDAP.BindDN = val
			} else {
				c.LDAP.BindDN = *argServerLDAPBindDN
			}
			if val := os.Getenv("LDAP_BINDPW_PATH"); val != "" {
				c.LDAP.BindPWPATH = val
			} else {
				c.LDAP.BindPWPATH = *argServerLDAPBindPWPATH
			}
			if val := os.Getenv("LDAP_FILTER"); val != "" {
				c.LDAP.Filter = val
			} else {
				c.LDAP.Filter = *argServerLDAPFilter
			}
			if val := os.Getenv("LDAP_RESULT_ATTRIBUTE"); val != "" {
				c.LDAP.ResultAttr = []string{val}
			} else {
				c.LDAP.ResultAttr = []string{*argServerLDAPResultAttr}
			}
			if val := os.Getenv("LDAP_STARTTLS"); val != "" {
				p, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err)
				}
				c.LDAP.StartTLS = p
			} else {
				c.LDAP.StartTLS = *argServerLDAPStartTLS
			}
			if val := os.Getenv("LDAP_SKIP_TLS_VERIFY"); val != "" {
				p, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err)
				}
				c.LDAP.TLSSkipVerify = p
			} else {
				c.LDAP.TLSSkipVerify = *argServerLDAPTLSVerify
			}
			if val := os.Getenv("LDAP_TLS_CAFILE"); val != "" {
				c.LDAP.TLSCAFile = val
			} else {
				c.LDAP.TLSCAFile = *argServerLDAPTLSCAFile
			}
			if val := os.Getenv("LDAP_TLS_CLIENT_CERT"); val != "" {
				c.LDAP.TLSClientCert = val
			} else {
				c.LDAP.TLSClientCert = *argServerLDAPTLSClientCert
			}
			if val := os.Getenv("LDAP_TLS_CLIENT_KEY"); val != "" {
				c.LDAP.TLSClientKey = val
			} else {
				c.LDAP.TLSClientKey = *argServerLDAPTLSClientKey
			}
			if val := os.Getenv("LDAP_SASL_EXTERNAL"); val != "" {
				p, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err)
				}
				c.LDAP.SASLExternal = p
			} else {
				c.LDAP.SASLExternal = *argServerLDAPSASLExternal
			}
			if val := os.Getenv("LDAP_SCOPE"); val != "" {
				switch val {
				case "base":
					c.LDAP.Scope = ldap.ScopeBaseObject
				case "one":
					c.LDAP.Scope = ldap.ScopeSingleLevel
				case "sub":
					c.LDAP.Scope = ldap.ScopeWholeSubtree
				default:
					log.Fatalln(parser.Usage(fmt.Sprintf("value '%s' must be one of: one, base or sub", val)))
				}
			} else {
				switch *argServerLDAPScope {
				case "base":
					c.LDAP.Scope = ldap.ScopeBaseObject
				case "one":
					c.LDAP.Scope = ldap.ScopeSingleLevel
				case "sub":
					c.LDAP.Scope = ldap.ScopeWholeSubtree
				}
			}
		}
	}

	if commandReload.Happened() {
		if val := os.Getenv("HTTP_URI"); val != "" {
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

	if commandStats.Happened() {
		if val := os.Getenv("HTTP_URI"); val != "" {
			c.HttpURI = val
		} else {
			if *argStatsHttpURI != "" {
				c.HttpURI = *argStatsHttpURI
			}
		}
		if strings.HasSuffix(c.HttpURI, "/") {
			c.HttpURI = c.HttpURI[:len(c.HttpURI)-1]
		}

		if *argStatsPrintWhitelist {
			c.CommandStatsOption.printWhitelist = true
		}
	}
}
