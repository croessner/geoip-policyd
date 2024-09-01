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
	RedisUsername string
	RedisPassword string

	// Redis for a replica (read-only) server pool
	RedisAddressRO string
	RedisPortRO    int

	RedisSentinels          []string
	RedisSentinelMasterName string
	RedisSentinelUsername   string
	RedisSentinelPassword   string

	RedisPrefix string
	RedisDB     int
	RedisTTL    int

	GeoipPath        string
	MaxCountries     int
	MaxIPs           int
	HomeCountries    []string
	MaxHomeCountries int
	MaxHomeIPs       int
	IgnoreNets       []string
	BlockPermanent   bool
	VerboseLevel     int

	// Flag that indicates which command was called
	CommandServer bool

	UseCDB  bool
	CDBPath string

	UseLDAP bool
	*LdapConf

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

	// ForceUserKnown represents a boolean flag indicating whether the user is known or not.
	ForceUserKnown bool
}

type CustomSettings struct {
	Data []Account `json:"data"`
}

type HomeCountries struct {
	Codes     []string `json:"codes"`
	IPs       int      `json:"ips"`
	Countries int      `json:"countries"`
}

type Account struct {
	Comment          string   `json:"comment"`
	Sender           string   `json:"sender"`
	IPs              int      `json:"ips"`
	Countries        int      `json:"countries"`
	TrustedCountries []string `json:"trusted_countries"` //nolint:tagliatelle // No camel case
	TrustedIPs       []string `json:"trusted_ips"`       //nolint:tagliatelle // No camel case
	*HomeCountries   `json:"home_countries"`
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

	/*
	 * Redis options for replica (read-only) requests
	 */
	argServerRedisAddressRO := commandServer.String(
		"", "redis-replica-address", &argparse.Options{
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
			Help: "IPv4 or IPv6 address for a Redis service (replica)",
		})
	argServerRedisPortRO := commandServer.Int(
		"", "redis-replica-port", &argparse.Options{
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
			Help: "Port for a Redis service (replica)",
		})

	/*
	 * Common Redis options
	 */
	argServerRedisSentinels := commandServer.StringList(
		"", "redis-sentinels", &argparse.Options{
			Required: false,
			Default:  []string{},
			Help:     "List of space separated sentinel servers",
		})
	argServerRedisSentinelMasterName := commandServer.String(
		"", "redis-sentinel-master-name", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Sentinel master name",
		})
	argServerRedisSentinelUsername := commandServer.String(
		"", "redis-sentinel-username", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis sentinel username",
		})
	argServerRedisSentinelPassword := commandServer.String(
		"", "redis-sentinel-password", &argparse.Options{
			Required: false,
			Default:  "",
			Help:     "Redis sentinel password",
		})
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
				} else if arg < 0 { //nolint:gomnd // Threshold value
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
				} else if arg < 0 {
					return errMaxIPs
				}

				return nil
			},
			Help: "Maximum number of IP addresses before rejecting e-mails",
		})
	argServerHomeCountries := commandServer.StringList(
		"", "home-countries", &argparse.Options{
			Required: false,
			Default:  []string{},
			Help:     "List of known home country codes",
		})
	argServerMaxHomeCountries := commandServer.Int(
		"", "max-home-countries", &argparse.Options{
			Required: false,
			Default:  maxCountries,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if arg < 0 { //nolint:gomnd // Threshold value
					return errMaxCountries
				}

				return nil
			},
			Help: "Maximum number home of countries before rejecting e-mails",
		})
	argServerMaxHomeIPs := commandServer.Int(
		"", "max-home-ips", &argparse.Options{
			Required: false,
			Default:  maxIPs,
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if arg < 0 {
					return errMaxIPs
				}

				return nil
			},
			Help: "Maximum number of home IP addresses before rejecting e-mails",
		})
	argServerIgnoreNets := commandServer.StringList(
		"", "ignore-network", &argparse.Options{
			Required: false,
			Default:  []string{},
			Help:     "List of IP addresses and networks to ignore",
		})
	argServerBlockedNoExpire := commandServer.Flag(
		"", "block-permanent", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Do not expire senders from Redis, if they were blocked in the past",
		})
	argServerForceUserKnown := commandServer.Flag(
		"", "force-user-known", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Senders are already known by an upstream service",
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
	argServerUseCDB := commandServer.Flag(
		"", "use-cdb", &argparse.Options{
			Required: false,
			Default:  false,
			Help:     "Enable CDB support",
		})
	argServerCDBPath := commandServer.String(
		"", "cdb-path", &argparse.Options{
			Required: false,
			Validate: func(opt []string) error {
				if _, err := os.Stat(opt[0]); os.IsNotExist(err) {
					return errFileNotFound
				}

				return nil
			},
			Help: "Full path to the cdb file",
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
	argServerLDAPIdlePoolSize := commandServer.Int(
		"", "ldap-idle-pool-size", &argparse.Options{
			Required: false,
			Default:  int(ldapPoolSize * 0.3),
			Validate: func(opt []string) error {
				if arg, err := strconv.Atoi(opt[0]); err != nil {
					return errNotInteger
				} else if arg < 0 {
					return errIdlePoolSize
				}

				return nil
			},
			Help: "LDAP pre-forked (idle) pool size",
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
			Help: "LDAP max pool size",
		})

	if *argServerLDAPIdlePoolSize > *argServerLDAPPoolSize {
		*argServerLDAPIdlePoolSize = *argServerLDAPPoolSize
	}

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

		if val := os.Getenv("GEOIPPOLICYD_REDIS_REPLICA_ADDRESS"); val != "" {
			c.RedisAddressRO = val
		} else {
			c.RedisAddressRO = *argServerRedisAddressRO
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_REPLICA_PORT"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_REDIS_REPLICA_PORT can not be used:", parser.Usage(err.Error()))
			}

			c.RedisPortRO = param
		} else {
			c.RedisPortRO = *argServerRedisPortRO
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_SENTINELS"); val != "" {
			c.RedisSentinels = strings.Split(val, " ")
		} else {
			c.RedisSentinels = *argServerRedisSentinels
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_SENTINEL_MASTER_NAME"); val != "" {
			c.RedisSentinelMasterName = val
		} else {
			c.RedisSentinelMasterName = *argServerRedisSentinelMasterName
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_SENTINEL_USERNAME"); val != "" {
			c.RedisSentinelUsername = val
		} else {
			c.RedisSentinelUsername = *argServerRedisSentinelUsername
		}

		if val := os.Getenv("GEOIPPOLICYD_REDIS_SENTINEL_PASSWORD"); val != "" {
			c.RedisSentinelPassword = val
		} else {
			c.RedisSentinelPassword = *argServerRedisSentinelPassword
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

		if val := os.Getenv("GEOIPPOLICYD_HOME_COUNTRIES"); val != "" {
			c.HomeCountries = strings.Split(val, " ")
		} else {
			c.HomeCountries = *argServerHomeCountries
		}

		if val := os.Getenv("GEOIPPOLICYD_MAX_HOME_COUNTRIES"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_MAX_HOME_COUNTRIES can not be used:", parser.Usage(err.Error()))
			}

			c.MaxHomeCountries = param
		} else {
			c.MaxHomeCountries = *argServerMaxHomeCountries
		}

		if val := os.Getenv("GEOIPPOLICYD_MAX_HOME_IPS"); val != "" {
			param, err := strconv.Atoi(val)
			if err != nil {
				log.Fatalln("Error: GEOIPPOLICYD_MAX_HOME_IPS can not be used:", parser.Usage(err.Error()))
			}

			c.MaxHomeIPs = param
		} else {
			c.MaxHomeIPs = *argServerMaxHomeIPs
		}

		if val := os.Getenv("GEOIPPOLICYD_BLOCK_PERMANENT"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.BlockPermanent = param
		} else {
			c.BlockPermanent = *argServerBlockedNoExpire
		}

		if val := os.Getenv("GEOIPPOLICYD_FORCE_USER_KNOWN"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.ForceUserKnown = param
		} else {
			c.ForceUserKnown = *argServerForceUserKnown
		}

		if val := os.Getenv("GEOIPPOLICYD_IGNORE_NETWORKS"); val != "" {
			c.IgnoreNets = strings.Split(val, " ")
		} else {
			c.IgnoreNets = *argServerIgnoreNets
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

		if val := os.Getenv("GEOIPPOLICYD_USE_CDB"); val != "" {
			param, err := strconv.ParseBool(val)
			if err != nil {
				log.Fatalln("Error:", err.Error())
			}

			c.UseCDB = param
		} else {
			c.UseCDB = *argServerUseCDB
		}

		if val := os.Getenv("GEOIPPOLICYD_CDB_PATH"); val != "" {
			c.CDBPath = val
		} else {
			c.CDBPath = *argServerCDBPath
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
			c.LdapConf = &LdapConf{}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_SERVER_URIS"); val != "" {
				param := strings.Split(val, ",")
				for i, uri := range param {
					param[i] = strings.TrimSpace(uri)
				}

				c.LdapConf.ServerURIs = param
			} else {
				c.LdapConf.ServerURIs = *argServerLDAPServerURIs
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_BASEDN"); val != "" {
				c.LdapConf.BaseDN = val
			} else {
				c.LdapConf.BaseDN = *argServerLDAPBaseDN
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_BINDDN"); val != "" {
				c.LdapConf.BindDN = val
			} else {
				c.LdapConf.BindDN = *argServerLDAPBindDN
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_BINDPW"); val != "" {
				c.LdapConf.BindPW = val
			} else {
				c.LdapConf.BindPW = *argServerLDAPBindPWPATH
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_FILTER"); val != "" {
				c.LdapConf.Filter = val
			} else {
				c.LdapConf.Filter = *argServerLDAPFilter
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_RESULT_ATTRIBUTE"); val != "" {
				c.LdapConf.SearchAttributes = []string{val}
			} else {
				c.LdapConf.SearchAttributes = []string{*argServerLDAPResultAttr}
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_STARTTLS"); val != "" {
				param, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err.Error())
				}

				c.LdapConf.StartTLS = param
			} else {
				c.LdapConf.StartTLS = *argServerLDAPStartTLS
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_TLS_SKIP_VERIFY"); val != "" {
				param, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err.Error())
				}

				c.LdapConf.TLSSkipVerify = param
			} else {
				c.LdapConf.TLSSkipVerify = *argServerLDAPTLSVerify
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_TLS_CAFILE"); val != "" {
				c.LdapConf.TLSCAFile = val
			} else {
				c.LdapConf.TLSCAFile = *argServerLDAPTLSCAFile
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_TLS_CLIENT_CERT"); val != "" {
				c.LdapConf.TLSClientCert = val
			} else {
				c.LdapConf.TLSClientCert = *argServerLDAPTLSClientCert
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_TLS_CLIENT_KEY"); val != "" {
				c.LdapConf.TLSClientKey = val
			} else {
				c.LdapConf.TLSClientKey = *argServerLDAPTLSClientKey
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_SASL_EXTERNAL"); val != "" {
				param, err := strconv.ParseBool(val)
				if err != nil {
					log.Fatalln("Error:", err.Error())
				}

				c.LdapConf.SASLExternal = param
			} else {
				c.LdapConf.SASLExternal = *argServerLDAPSASLExternal
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_SCOPE"); val != "" {
				switch val {
				case BASE:
					c.LdapConf.Scope = ldap.ScopeBaseObject
				case ONE:
					c.LdapConf.Scope = ldap.ScopeSingleLevel
				case SUB:
					c.LdapConf.Scope = ldap.ScopeWholeSubtree
				default:
					log.Fatalln(parser.Usage(fmt.Sprintf("value '%s' must be one of: one, base or sub", val)))
				}
			} else {
				switch *argServerLDAPScope {
				case BASE:
					c.LdapConf.Scope = ldap.ScopeBaseObject
				case ONE:
					c.LdapConf.Scope = ldap.ScopeSingleLevel
				case SUB:
					c.LdapConf.Scope = ldap.ScopeWholeSubtree
				}
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_IDLE_POOL_SIZE"); val != "" {
				param, err := strconv.Atoi(val)
				if err != nil {
					log.Fatalln("Error: GEOIPPOLICYD_LDAP_IDLE_POOL_SIZE can not be used:", parser.Usage(err.Error()))
				}

				c.LdapConf.IdlePoolSize = param
			} else {
				c.LdapConf.IdlePoolSize = *argServerLDAPIdlePoolSize
			}

			if val := os.Getenv("GEOIPPOLICYD_LDAP_POOL_SIZE"); val != "" {
				param, err := strconv.Atoi(val)
				if err != nil {
					log.Fatalln("Error: GEOIPPOLICYD_LDAP_POOL_SIZE can not be used:", parser.Usage(err.Error()))
				}

				c.LdapConf.PoolSize = param
			} else {
				c.LdapConf.PoolSize = *argServerLDAPPoolSize
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
