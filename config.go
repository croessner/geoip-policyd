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
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/akamensky/argparse"
	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
)

const Localhost4 = "127.0.0.1"

// Defaults.
const (
	serverAddress  = Localhost4
	serverPort     = 4646
	redisAddress   = Localhost4
	redisPort      = 6379
	geoipPath      = "/usr/share/GeoIP/GeoLite2-City.mmdb"
	redisPrefix    = "geopol_"
	redisTTL       = 3600
	maxCountries   = 3
	maxIPs         = 10
	httpAddress    = Localhost4
	httpPort       = 8080
	httpX509Cert   = "/localhost.pem"
	httpX509Key    = "/localhost-key.pem"
	ldapPoolSize   = 10
	ldapMaxRetries = 9
	mailPort       = 587
	mailSubject    = "[geoip-policyd] An e-mail account was compromised"
	mailHelo       = "localhost"
)

const (
	logLevelNone  = iota
	logLevelInfo  = iota
	logLevelDebug = iota
)

const (
	BASE = "base"
	ONE  = "one"
	SUB  = "sub"
)

type ConnProtocol struct {
	name string
}

func (c *ConnProtocol) String() string {
	return c.name
}

func (c *ConnProtocol) Set(value string) error {
	switch value {
	case "tcp", "tcp6", "unix":
		c.name = value
	default:
		return errWrongProtocol
	}

	return nil
}

func (c *ConnProtocol) Type() string {
	return "ConnProtocol"
}

func (c *ConnProtocol) Get() string {
	return c.name
}

type CmdLineConfig struct {
	// Listen address for the policy service
	ServerAddress string

	// Prt number for the policy service
	ServerPort int

	// REST interface of the policy service
	HTTPAddress string
	HTTPPort    int
	HTTPApp

	// Use 'sender' or 'sasl_username' attribute?
	UseSASLUsername bool

	// Redis settings for a reading and/or writing server pool
	RedisAddress  string
	RedisPort     int
	RedisDB       int
	RedisUsername string
	RedisPassword string
	RedisProtocol ConnProtocol

	// Redis for a writing server pool
	RedisAddressW  string
	RedisPortW     int
	RedisDBW       int
	RedisUsernameW string
	RedisPasswordW string
	RedisProtocolW ConnProtocol

	RedisPrefix string
	RedisTTL    int

	GeoipPath       string
	MaxCountries    int
	MaxIPs          int
	BlockedNoExpire bool
	VerboseLevel    int

	// Flag that indicates which command was called
	CommandServer bool

	UseLDAP bool
	LDAP

	LogFormatJSON      bool
	CustomSettingsPath string

	// Global flag that indicates if any action should be taken
	RunActions bool

	// Flag that indicates, if the operator action should be taken
	RunActionOperator bool

	// Action that sends a notification to an operator
	EmailOperatorTo          string
	EmailOperatorFrom        string
	EmailOperatorSubject     string
	EmailOperatorMessageCT   string
	EmailOperatorMessagePath string

	// Global mail server configuration parameters
	MailServer   string
	MailHelo     string
	MailPort     int
	MailUsername string
	MailPassword string
	MailSSL      bool
}

type CustomSettings struct {
	Data []Account `json:"data"`
}

type Account struct {
	Comment          string   `json:"comment"`
	Sender           string   `json:"sender"`
	IPs              int      `json:"ips"`
	Countries        int      `json:"countries"`
	TrustedCountries []string `json:"trusted_countries"` //nolint:tagliatelle // No camel case
	TrustedIPs       []string `json:"trusted_ips"`       //nolint:tagliatelle // No camel case
}

func (c *CmdLineConfig) String() string {
	var result string

	value := reflect.ValueOf(*c)
	typeOfC := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfC.Field(index).Name {
		case "CommandServer", "UseLDAP", "LDAP", "MailPassword", "HTTPApp", "VerboseLevel":
			continue
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfC.Field(index).Name, value.Field(index).Interface())
		}
	}

	return result[1:]
}

//nolint:gocognit,gocyclo,maintidx // Ignore complexity
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
						return errNotIPOrHostname
					}
				}

				return nil
			},
			Help: "IPv4 or IPv6 address for the policy service",
		})
	argServerPort := commandServer.Int(
		"p", "server-port", &argparse.Options{
			Required: false,
			Default:  serverPort,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if !(arg > 0 && arg <= 65535) {
					return errNotValidPortNumber
				}

				return nil
			},
			Help: "Port for the policy service",
		})
	argServerHTTPAddress := commandServer.String(
		"", "http-address", &argparse.Options{
			Required: false,
			Default:  httpAddress,
			Help:     "HTTP address for incoming requests",
		})
	argHTTPPort := commandServer.Int(
		"", "http-port", &argparse.Options{
			Required: false,
			Default:  httpPort,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if !(arg > 0 && arg <= 65535) {
					return errNotValidPortNumber
				}

				return nil
			},
			Help: "HTTP port for incoming requests",
		})

	argServerUseSASLUsername := commandServer.Flag(
		"", "sasl-username", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Use 'sasl_username' instead of the 'sender' attribute",
		})

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
						return errNotIPOrHostname
					}
				}

				return nil
			},
			Help: "IPv4 or IPv6 address for the Redis service",
		})
	argServerRedisPort := commandServer.Int(
		"P", "redis-port", &argparse.Options{
			Required: false,
			Default:  redisPort,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if !(arg > 0 && arg <= 65535) {
					return errNotValidPortNumber
				}

				return nil
			},
			Help: "Port for the Redis service",
		})
	argServerRedisDB := commandServer.Int(
		"", "redis-database-number", &argparse.Options{
			Required: false,
			Default:  0,
			Help:     "Redis database number",
		})
	argServerRedisUsername := commandServer.String(
		"", "redis-username", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis username",
		})
	argServerRedisPassword := commandServer.String(
		"", "redis-password", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis password",
		})
	argServerRedisProtocol := commandServer.String(
		"", "redis-protocol", &argparse.Options{
			Required: false,
			Default:  "tcp",
			Help:     "Redis connection protocol; one of 'tcp', 'tcp6' or 'unix'",
		})

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
						return errNotIPOrHostname
					}
				}

				return nil
			},
			Help: "IPv4 or IPv6 address for a Redis service (writer)",
		})
	argServerRedisPortW := commandServer.Int(
		"", "redis-writer-port", &argparse.Options{
			Required: false,
			Default:  redisPort,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if !(arg > 0 && arg <= 65535) {
					return errNotValidPortNumber
				}

				return nil
			},
			Help: "Port for a Redis service (writer)",
		})
	argServerRedisDBW := commandServer.Int(
		"", "redis-writer-database-number", &argparse.Options{
			Required: false,
			Default:  0,
			Help:     "Redis database number (writer)",
		})
	argServerRedisUsernameW := commandServer.String(
		"", "redis-writer-username", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis username (writer)",
		})
	argServerRedisPasswordW := commandServer.String(
		"", "redis-writer-password", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis password (writer)",
		})
	argServerRedisProtocolW := commandServer.String(
		"", "redis-writer-protocol", &argparse.Options{
			Required: false,
			Default:  "tcp",
			Help:     "Redis connection protocol (writer); one of 'tcp', 'tcp6' or 'unix'",
		})

	/*
	 * Common Redis options
	 */
	argServerRedisPrefix := commandServer.String(
		"", "redis-prefix", &argparse.Options{
			Required: false,
			Default:  redisPrefix,
			Help:     "Redis prefix",
		})
	argServerRedisTTL := commandServer.Int(
		"", "redis-ttl", &argparse.Options{
			Required: false,
			Default:  redisTTL,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if arg < 1 {
					return errNotValidPortNumber
				}

				return nil
			},
			Help: "Redis TTL in seconds",
		})

	/*
	 * Other config options
	 */
	argServerGeoIPDB := commandServer.String(
		"g", "geoip-path", &argparse.Options{
			Required: false,
			Default:  geoipPath,
			Validate: func(opt []string) error {
				if _, err := os.Stat(opt[0]); os.IsNotExist(err) {
					return errFileNotFound
				}

				return nil
			},
			Help: "Full path to the GeoIP database file",
		})
	argServerMaxCountries := commandServer.Int(
		"", "max-countries", &argparse.Options{
			Required: false,
			Default:  maxCountries,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if arg < 2 { //nolint:gomnd // Threshold value
					return errMaxCountries
				}

				return nil
			},
			Help: "Maximum number of countries before rejecting e-mails",
		})
	argServerMaxIPs := commandServer.Int(
		"", "max-ips", &argparse.Options{
			Required: false,
			Default:  maxIPs,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if arg < 1 {
					return errMaxIPs
				}

				return nil
			},
			Help: "Maximum number of IP addresses before rejecting e-mails",
		})
	argServerBlockedNoExpire := commandServer.Flag(
		"", "block-permanent", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Do not expire senders from Redis, if they were blocked in the past",
		})
	argServerCustomSettingsPath := commandServer.String(
		"c", "custom-settings-path", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Custom settings with different IP and country limits",
		})
	argServerHTTPUseBasicAuth := commandServer.Flag(
		"", "http-use-basic-auth", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Enable basic HTTP auth",
		})
	argServerHTTPUseSSL := commandServer.Flag(
		"", "http-use-ssl", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Enable HTTPS",
		})
	argServerHTTPBasicAuthUsername := commandServer.String(
		"", "http-basic-auth-username", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "HTTP basic auth username",
		})
	argServerHTTPBasicAuthPassword := commandServer.String(
		"", "http-basic-auth-password", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "HTTP basic auth password",
		})
	argServerHTTPTLSCert := commandServer.String(
		"", "http-tls-cert", &argparse.Options{
			Required: false,
			Default:  httpX509Cert,
			Help:     "HTTP TLS server certificate (full chain)",
		})
	argServerHTTPTLSKey := commandServer.String(
		"", "http-tls-key", &argparse.Options{
			Required: false,
			Default:  httpX509Key,
			Help:     "HTTP TLS server key",
		})
	argServerUseLDAP := commandServer.Flag(
		"", "use-ldap", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Enable LDAP support",
		})
	argServerLDAPServerURIs := commandServer.StringList(
		"", "ldap-server-uri", &argparse.Options{
			Required: false,
			Default:  []string{"ldap://127.0.0.1:389/"},
			Help:     "Server URI. Specify multiple times, if you need more than one server",
		})
	argServerLDAPBaseDN := commandServer.String(
		"", "ldap-basedn", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Base DN",
		})
	argServerLDAPBindDN := commandServer.String(
		"", "ldap-binddn", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "bind DN",
		})
	argServerLDAPBindPWPATH := commandServer.String(
		"", "ldap-bindpw", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "bind password",
		})
	argServerLDAPFilter := commandServer.String(
		"", "ldap-filter", &argparse.Options{
			Required: false,
			Default:  "(&(objectClass=*)(mailAlias=%s))",
			Help:     "Filter with %s placeholder",
		})
	argServerLDAPResultAttr := commandServer.String(
		"", "ldap-result-attribute", &argparse.Options{
			Required: false,
			Default:  "mailAccount",
			Help:     "Result attribute for the requested mail sender",
		})
	argServerLDAPStartTLS := commandServer.Flag(
		"", "ldap-starttls", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "If this option is given, use StartTLS",
		})
	argServerLDAPTLSVerify := commandServer.Flag(
		"", "ldap-tls-skip-verify", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Skip TLS server name verification",
		})
	argServerLDAPTLSCAFile := commandServer.String(
		"", "ldap-tls-cafile", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "File containing TLS CA certificate(s)",
		})
	argServerLDAPTLSClientCert := commandServer.String(
		"", "ldap-tls-client-cert", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "File containing a TLS client certificate",
		})
	argServerLDAPTLSClientKey := commandServer.String(
		"", "ldap-tls-client-key", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "File containing a TLS client key",
		})
	argServerLDAPSASLExternal := commandServer.Flag(
		"", "ldap-sasl-external", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Use SASL/EXTERNAL instead of a simple bind",
		})
	argServerLDAPScope := commandServer.String(
		"", "ldap-scope", &argparse.Options{
			Required: false,
			Default:  "sub",
			Validate: func(opt []string) error {
				switch opt[0] {
				case BASE, ONE, SUB:
					return nil
				default:
					return errLDAPScope
				}
			},
			Help: "LDAP search scope [base, one, sub]",
		})
	argServerLDAPPoolSize := commandServer.Int(
		"", "ldap-pool-size", &argparse.Options{
			Required: false,
			Default:  ldapPoolSize,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if arg < 1 {
					return errPoolSize
				}

				return nil
			},
			Help: "LDAP pre-forked pool size",
		})

	argVerbose := parser.FlagCounter(
		"v", "verbose", &argparse.Options{
			Help: "Verbose mode. Repeat this for an increased log level",
		})
	argServerLogFormatJSON := commandServer.Flag(
		"", "log-json", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Enable JSON log format",
		})
	argVersion := parser.Flag(
		"", "version", &argparse.Options{
			Help: "Current version",
		})

	argServerRunActions := commandServer.Flag(
		"", "run-actions", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Run actions, if a sender is over limits",
		})
	argServerRunActionOperator := commandServer.Flag(
		"", "run-action-operator", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Run the operator action",
		})
	argServerOperatorTo := commandServer.String(
		"", "operator-to", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "E-Mail To-header for the operator action",
		})
	argServerOperatorFrom := commandServer.String(
		"", "operator-from", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "E-Mail From-header for the operator action",
		})
	argServerOperatorSubject := commandServer.String(
		"", "operator-subject", &argparse.Options{
			Required: false,
			Default:  mailSubject,
			Help:     "E-Mail Subject-header for the operator action",
		})
	argServerOperatorMessageCT := commandServer.String(
		"", "operator-message-ct", &argparse.Options{
			Required: false,
			Default:  "text/plain",
			Help:     "E-Mail Content-Type-header for the operator action",
		})
	argServerOperatorMessagePath := commandServer.String(
		"", "operator-message-path", &argparse.Options{
			Required: false,
			Default:  "",
			Validate: func(opt []string) error {
				if _, err := os.Stat(opt[0]); os.IsNotExist(err) {
					return errFileNotFound
				}

				return nil
			},
			Help: "Full path to the e-mail message file for the operator action",
		})

	argServerMailServer := commandServer.String(
		"", "mail-server-address", &argparse.Options{
			Required: false,
			Default:  "",
			Validate: func(opt []string) error {
				if addr := net.ParseIP(opt[0]); addr == nil {
					if _, err := net.LookupHost(opt[0]); err != nil {
						return errNotIPOrHostname
					}
				}

				return nil
			},
			Help: "E-mail server address for notifications",
		})
	argServerMailPort := commandServer.Int(
		"", "mail-server-port", &argparse.Options{
			Required: false,
			Default:  mailPort,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if !(arg > 0 && arg <= 65535) {
					return errNotValidPortNumber
				}

				return nil
			},
			Help: "E-mail server port number",
		})
	argServerMailHelo := commandServer.String(
		"", "mail-helo", &argparse.Options{
			Required: false,
			Default:  mailHelo,
			Help:     "E-mail server HELO/EHLO hostname",
		})
	argServerMailUsername := commandServer.String(
		"", "mail-username", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "E-mail server username",
		})
	argServerMailPasswordPath := commandServer.String(
		"", "mail-password", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "E-mail server password",
		})
	argServerMailSSL := commandServer.Flag(
		"", "mail-ssl-on-connect", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Use SSL/TLS on connect for the e-mail server",
		})

	err := parser.Parse(args)
	if err != nil {
		log.Fatalln(parser.Usage(err.Error()))
	}

	if *argVersion {
		fmt.Println("Version:", version) //nolint:forbidigo // Printing a version number is okay
		os.Exit(0)
	}

	if val := os.Getenv("GEOIPPOLICYD_VERBOSE_LEVEL"); val != "" {
		switch val {
		case "none":
			c.VerboseLevel = logLevelNone
		case "info":
			c.VerboseLevel = logLevelInfo
		case "debug":
			c.VerboseLevel = logLevelDebug
		}
	} else {
		switch *argVerbose {
		case logLevelNone:
			c.VerboseLevel = logLevelNone
		case logLevelInfo:
			c.VerboseLevel = logLevelInfo
		case logLevelDebug:
			c.VerboseLevel = logLevelDebug
		default:
			c.VerboseLevel = logLevelInfo
		}
	}

	if val := os.Getenv("GEOIPPOLICYD_LOG_JSON"); val != "" {
		param, err := strconv.ParseBool(val)
		if err != nil {
			log.Fatalln("Error:", err.Error())
		}

		c.LogFormatJSON = param
	} else {
		c.LogFormatJSON = *argServerLogFormatJSON
	}

	c.CommandServer = commandServer.Happened()

	if commandServer.Happened() {
		if val := os.Getenv("GEOIPPOLICYD_SERVER_ADDRESS"); val != "" {
			c.ServerAddress = val
		} else {
			c.ServerAddress = *argServerAddress
		}

		if val := os.Getenv("GEOIPPOLICYD_SERVER_PORT"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_SERVER_PORT an not be used:", parser.Usage(err.Error()))
			}

			c.ServerPort = param
		} else {
			c.ServerPort = *argServerPort
		}

		if val := os.Getenv("GEOIPPOLICYD_HTTP_ADDRESS"); val != "" {
			c.HTTPAddress = val
		} else {
			c.HTTPAddress = *argServerHTTPAddress
		}

		if val := os.Getenv("GEOIPPOLICYD_HTTP_PORT"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_HTTP_PORT an not be used:", parser.Usage(err.Error()))
			}

			c.HTTPPort = param
		} else {
			c.HTTPPort = *argHTTPPort
		}

		if val := os.Getenv("GEOIPPOLICYD_USE_SASL_USERNAME"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.UseSASLUsername = param
		} else {
			c.UseSASLUsername = *argServerUseSASLUsername
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_ADDRESS"); val != "" {
			c.RedisAddress = val
		} else {
			c.RedisAddress = *argServerRedisAddress
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_PORT"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_REDIS_PORT can not be used:", parser.Usage(err.Error()))
			}

			c.RedisPort = param
		} else {
			c.RedisPort = *argServerRedisPort
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_DATABASE_NUMBER"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_REDIS_DATABASE_NUMBER can not be used:", parser.Usage(err.Error()))
			}

			c.RedisDB = param
		} else {
			c.RedisDB = *argServerRedisDB
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_USERNAME"); val != "" {
			c.RedisUsername = val
		} else {
			c.RedisUsername = *argServerRedisUsername
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_PASSWORD"); val != "" {
			c.RedisPassword = val
		} else {
			c.RedisPassword = *argServerRedisPassword
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_PROTOCOL"); val != "" {
			if err := c.RedisProtocol.Set(val); err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_REDIS_PROTOCOL can not be used:", parser.Usage(err.Error()))
			}
		} else if err := c.RedisProtocol.Set(*argServerRedisProtocol); err != nil {
			log.Fatalln("Error: GEOIPPOLICYD_REDIS_PROTOCOL can not be used:", parser.Usage(err.Error()))
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_WRITER_ADDRESS"); val != "" {
			c.RedisAddressW = val
		} else {
			c.RedisAddressW = *argServerRedisAddressW
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_WRITER_PORT"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_REDIS_WRITER_PORT can not be used:", parser.Usage(err.Error()))
			}

			c.RedisPortW = param
		} else {
			c.RedisPortW = *argServerRedisPortW
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_WRITER_DATABASE_NUMBER"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_REDIS_WRITER_DATABASE_NUMBER can not be used:",
					parser.Usage(err.Error()))
			}

			c.RedisDBW = param
		} else {
			c.RedisDBW = *argServerRedisDBW
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_WRITER_USERNAME"); val != "" {
			c.RedisUsernameW = val
		} else {
			c.RedisUsernameW = *argServerRedisUsernameW
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_WRITER_PASSWORD"); val != "" {
			c.RedisPasswordW = val
		} else {
			c.RedisPasswordW = *argServerRedisPasswordW
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_WRITER_PROTOCOL"); val != "" {
			if err := c.RedisProtocolW.Set(val); err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_REDIS_PROTOCOL can not be used:", parser.Usage(err.Error()))
			}
		} else if err := c.RedisProtocolW.Set(*argServerRedisProtocolW); err != nil {
			log.Fatalln("Error: GEOIPPOLICYD_REDIS_WRITER_PROTOCOL can not be used:", parser.Usage(err.Error()))
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_PREFIX"); val != "" {
			c.RedisPrefix = val
		} else {
			c.RedisPrefix = *argServerRedisPrefix
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_TTL"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_REDIS_TTL can not be used:", parser.Usage(err.Error()))
			}

			c.RedisTTL = param
		} else {
			c.RedisTTL = *argServerRedisTTL
		}

		if val := os.Getenv("GEOIPPOLICYD_GEOIP_PATH"); val != "" {
			c.GeoipPath = val
		} else {
			c.GeoipPath = *argServerGeoIPDB
		}

		if val := os.Getenv("GEOIPPOLICYD_MAX_COUNTRIES"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_MAX_COUNTRIES can not be used:", parser.Usage(err.Error()))
			}

			c.MaxCountries = param
		} else {
			c.MaxCountries = *argServerMaxCountries
		}

		if val := os.Getenv("GEOIPPOLICYD_MAX_IPS"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_MAX_IPS can not be used:", parser.Usage(err.Error()))
			}

			c.MaxIPs = param
		} else {
			c.MaxIPs = *argServerMaxIPs
		}

		if val := os.Getenv("GEOIPPOLICYD_BLOCK_PERMANENT"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.BlockedNoExpire = param
		} else {
			c.BlockedNoExpire = *argServerBlockedNoExpire
		}

		if val := os.Getenv("GEOIPPOLICYD_CUSTOM_SETTINGS_PATH"); val != "" {
			c.CustomSettingsPath = val
		} else {
			c.CustomSettingsPath = *argServerCustomSettingsPath
		}

		if val := os.Getenv("GEOIPPOLICYD_HTTP_USE_BASIC_AUTH"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				level.Error(logger).Log("error", err.Error())
			}

			c.HTTPApp.useBasicAuth = param
		} else {
			c.HTTPApp.useBasicAuth = *argServerHTTPUseBasicAuth
		}

		if c.HTTPApp.useBasicAuth {
			if val := os.Getenv("GEOIPPOLICYD_HTTP_BASIC_AUTH_USERNAME"); val != "" {
				c.HTTPApp.auth.username = val
			} else {
				c.HTTPApp.auth.username = *argServerHTTPBasicAuthUsername
			}

			if val := os.Getenv("GEOIPPOLICYD_HTTP_BASIC_AUTH_PASSWORD"); val != "" {
				c.HTTPApp.auth.password = val
			} else {
				c.HTTPApp.auth.password = *argServerHTTPBasicAuthPassword
			}
		}

		if val := os.Getenv("GEOIPPOLICYD_HTTP_USE_SSL"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.HTTPApp.useSSL = param
		} else {
			c.HTTPApp.useSSL = *argServerHTTPUseSSL
		}

		if c.HTTPApp.useSSL {
			if val := os.Getenv("GEOIPPOLICYD_HTTP_TLS_CERT"); val != "" {
				c.HTTPApp.x509.cert = val
			} else {
				c.HTTPApp.x509.cert = *argServerHTTPTLSCert
			}

			if val := os.Getenv("GEOIPPOLICYD_HTTP_TLS_KEY"); val != "" {
				c.HTTPApp.x509.key = val
			} else {
				c.HTTPApp.x509.key = *argServerHTTPTLSKey
			}
		}

		if val := os.Getenv("GEOIPPOLICYD_USE_LDAP"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.UseLDAP = param
		} else {
			c.UseLDAP = *argServerUseLDAP
		}

		if c.UseLDAP {
			if val := os.Getenv("GEOIPPOLICYD_LDAP_SERVER_URIS"); val != "" {
				param := strings.Split(val, ",")
				for i, uri := range param {
					param[i] = strings.TrimSpace(uri)
				}

				c.LDAP.ServerURIs = param
			} else {
				c.LDAP.ServerURIs = *argServerLDAPServerURIs
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_BASEDN"); val != "" {
				c.LDAP.BaseDN = val
			} else {
				c.LDAP.BaseDN = *argServerLDAPBaseDN
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_BINDDN"); val != "" {
				c.LDAP.BindDN = val
			} else {
				c.LDAP.BindDN = *argServerLDAPBindDN
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_BINDPW"); val != "" {
				c.LDAP.BindPW = val
			} else {
				c.LDAP.BindPW = *argServerLDAPBindPWPATH
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_FILTER"); val != "" {
				c.LDAP.Filter = val
			} else {
				c.LDAP.Filter = *argServerLDAPFilter
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_RESULT_ATTRIBUTE"); val != "" {
				c.LDAP.ResultAttr = []string{val}
			} else {
				c.LDAP.ResultAttr = []string{*argServerLDAPResultAttr}
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_STARTTLS"); val != "" {
				param, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err.Error())
				}

				c.LDAP.StartTLS = param
			} else {
				c.LDAP.StartTLS = *argServerLDAPStartTLS
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_TLS_SKIP_VERIFY"); val != "" {
				param, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err.Error())
				}

				c.LDAP.TLSSkipVerify = param
			} else {
				c.LDAP.TLSSkipVerify = *argServerLDAPTLSVerify
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_TLS_CAFILE"); val != "" {
				c.LDAP.TLSCAFile = val
			} else {
				c.LDAP.TLSCAFile = *argServerLDAPTLSCAFile
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_TLS_CLIENT_CERT"); val != "" {
				c.LDAP.TLSClientCert = val
			} else {
				c.LDAP.TLSClientCert = *argServerLDAPTLSClientCert
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_TLS_CLIENT_KEY"); val != "" {
				c.LDAP.TLSClientKey = val
			} else {
				c.LDAP.TLSClientKey = *argServerLDAPTLSClientKey
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_SASL_EXTERNAL"); val != "" {
				param, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err.Error())
				}

				c.LDAP.SASLExternal = param
			} else {
				c.LDAP.SASLExternal = *argServerLDAPSASLExternal
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_SCOPE"); val != "" {
				switch val {
				case BASE:
					c.LDAP.Scope = ldap.ScopeBaseObject
				case ONE:
					c.LDAP.Scope = ldap.ScopeSingleLevel
				case SUB:
					c.LDAP.Scope = ldap.ScopeWholeSubtree
				default:
					log.Fatalln(parser.Usage(fmt.Sprintf("value '%s' must be one of: one, base or sub", val)))
				}
			} else {
				switch *argServerLDAPScope {
				case BASE:
					c.LDAP.Scope = ldap.ScopeBaseObject
				case ONE:
					c.LDAP.Scope = ldap.ScopeSingleLevel
				case SUB:
					c.LDAP.Scope = ldap.ScopeWholeSubtree
				}
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_POOL_SIZE"); val != "" {
				param, err := strconv.Atoi(val)
				if err != nil {
					log.Fatalln("Error: GEOIPPOLICYD_LDAP_POOL_SIZE can not be used:", parser.Usage(err.Error()))
				}

				c.LDAP.PoolSize = param
			} else {
				c.LDAP.PoolSize = *argServerLDAPPoolSize
			}
		}

		/*
		 * Actions
		 */

		if val := os.Getenv("GEOIPPOLICYD_RUN_ACTIONS"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.RunActions = param
		} else {
			c.RunActions = *argServerRunActions
		}

		if c.RunActions {
			if val := os.Getenv("GEOIPPOLICYD_RUN_ACTION_OPERATOR"); val != "" {
				param, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err.Error())
				}

				c.RunActionOperator = param
			} else {
				c.RunActionOperator = *argServerRunActionOperator
			}

			if c.RunActionOperator {
				if val := os.Getenv("GEOIPPOLICYD_OPERATOR_TO"); val != "" {
					c.EmailOperatorTo = val
				} else {
					c.EmailOperatorTo = *argServerOperatorTo
				}

				if val := os.Getenv("GEOIPPOLICYD_OPERATOR_FROM"); val != "" {
					c.EmailOperatorFrom = val
				} else {
					c.EmailOperatorFrom = *argServerOperatorFrom
				}

				if val := os.Getenv("GEOIPPOLICYD_OPERATOR_SUBJECT"); val != "" {
					c.EmailOperatorSubject = val
				} else {
					c.EmailOperatorSubject = *argServerOperatorSubject
				}

				if val := os.Getenv("GEOIPPOLICYD_OPERATOR_MESSAGE_CT"); val != "" {
					c.EmailOperatorMessageCT = val
				} else {
					c.EmailOperatorMessageCT = *argServerOperatorMessageCT
				}

				if val := os.Getenv("GEOIPPOLICYD_OPERATOR_MESSAGE_PATH"); val != "" {
					c.EmailOperatorMessagePath = val
				} else {
					c.EmailOperatorMessagePath = *argServerOperatorMessagePath
				}
			}
		}

		/*
		 * Mail server settings
		 */

		if val := os.Getenv("GEOIPPOLICYD_MAIL_SERVER_ADDRESS"); val != "" {
			c.MailServer = val
		} else {
			c.MailServer = *argServerMailServer
		}

		if val := os.Getenv("GEOIPPOLICYD_MAIL_HELO"); val != "" {
			c.MailHelo = val
		} else {
			c.MailHelo = *argServerMailHelo
		}

		if val := os.Getenv("GEOIPPOLICYD_MAIL_SERVER_PORT"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_MAIL_SERVER_PORT can not be used:", parser.Usage(err.Error()))
			}

			c.MailPort = param
		} else {
			c.MailPort = *argServerMailPort
		}

		if val := os.Getenv("GEOIPPOLICYD_MAIL_USERNAME"); val != "" {
			c.MailUsername = val
		} else {
			c.MailUsername = *argServerMailUsername
		}

		if val := os.Getenv("GEOIPPOLICYD_MAIL_PASSWORD"); val != "" {
			c.MailPassword = val
		} else {
			c.MailPassword = *argServerMailPasswordPath
		}

		if val := os.Getenv("GEOIPPOLICYD_MAIL_SSL_ON_CONNECT"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.MailSSL = param
		} else {
			c.MailSSL = *argServerMailSSL
		}
	}
}
