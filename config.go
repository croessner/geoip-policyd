package main

import (
	"encoding/json"
	"fmt"
	"github.com/akamensky/argparse"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
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
)

type Config struct {
	ServerAddress  string
	ServerPort     int

	RedisAddress   string
	RedisPort      int
	RedisDB        int
	RedisUsername  string
	RedisPassword  string

	RedisAddressW  string
	RedisPortW     int
	RedisDBW       int
	RedisUsernameW string
	RedisPasswordW string

	RedisPrefix    string
	RedisTTL       int

	GeoipPath      string
	MaxCountries   int
	MaxIps         int
	Verbose        bool
	WhiteList      Data
}

type Data struct {
	Data []Account `json:"data"`
}

type Account struct {
	Comment   string `json:"comment"`
	Sender    string `json:"sender"`
	Ips       int    `json:"ips"`
	Countries int    `json:"countries"`
}

var cfg Config
var data Data

func initConfig(args []string) {
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

	/*
	 * Redis options for read and/or write requests
	 */
	argRedisAddress := commandServer.String(
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
	argRedisPort := commandServer.Int(
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
	argRedisDB := commandServer.Int(
		"", "redis-database-number", &argparse.Options{
			Required: false,
			Help:     "Redis database number",
		},
	)
	argRedisUsername := commandServer.String(
		"", "redis-username", &argparse.Options{
			Required: false,
			Help:     "Redis username",
		},
	)
	argRedisPassword := commandServer.String(
		"", "redis-password", &argparse.Options{
			Required: false,
			Help:     "Redis password",
		},
	)

	/*
	 * Redis options for write requests
	 */
	argRedisAddressW := commandServer.String(
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
	argRedisPortW := commandServer.Int(
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
	argRedisDBW := commandServer.Int(
		"", "redis-writer-database-number", &argparse.Options{
			Required: false,
			Help:     "Redis database number (writer)",
		},
	)
	argRedisUsernameW := commandServer.String(
		"", "redis-writer-username", &argparse.Options{
			Required: false,
			Help:     "Redis username (writer)",
		},
	)
	argRedisPasswordW := commandServer.String(
		"", "redis-writer-password", &argparse.Options{
			Required: false,
			Help:     "Redis password (writer)",
		},
	)

	/*
	 * Common Redis options
	 */
	argRedisPrefix := commandServer.String(
		"", "redis-prefix", &argparse.Options{
			Required: false,
			Help:     "Redis prefix; default(" + redisPrefix + ")",
		},
	)
	argRedisTTL := commandServer.Int(
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
	argGeoIPDB := commandServer.String(
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
	argMaxCountries := commandServer.Int(
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
	argMaxIps := commandServer.Int(
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
	argWhiteList := commandServer.String(
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

	err := parser.Parse(args)
	if err != nil {
		log.Fatalln(parser.Usage(err))
	}

	// Map defaults
	cfg = Config{
		ServerAddress: serverAddress,
		ServerPort:    serverPort,
		RedisAddress:  redisAddress,
		RedisPort:     redisPort,
		RedisAddressW: redisAddress,
		RedisPortW:    redisPort,
		RedisPrefix:   redisPrefix,
		RedisTTL:      redisTTL,
		GeoipPath:     geoipPath,
		MaxCountries:  maxCountries,
		MaxIps:        maxIps,
	}

	if *argVersion {
		fmt.Println("Version:", version)
		os.Exit(0)
	}

	cfg.Verbose = *argVerbose

	if val := os.Getenv("SERVER_ADDRESS"); val != "" {
		cfg.ServerAddress = val
	} else {
		if *argServerAddress != "" {
			cfg.ServerAddress = *argServerAddress
		}
	}
	if val := os.Getenv("SERVER_PORT"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: SERVER_PORT an not be used:", parser.Usage(err))
		}
		cfg.ServerPort = p
	} else {
		if *argServerPort != 0 {
			cfg.ServerPort = *argServerPort
		}
	}

	if val := os.Getenv("REDIS_ADDRESS"); val != "" {
		cfg.RedisAddress = val
	} else {
		if *argRedisAddress != "" {
			cfg.RedisAddress = *argRedisAddress
		}
	}
	if val := os.Getenv("REDIS_PORT"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: REDIS_PORT can not be used:", parser.Usage(err))
		}
		cfg.RedisPort = p
	} else {
		if *argRedisPort != 0 {
			cfg.RedisPort = *argRedisPort
		}
	}
	if val := os.Getenv("REDIS_DATABASE_NUMBER"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: REDIS_DATABASE_NUMBER can not be used:", parser.Usage(err))
		}
		cfg.RedisDB = p
	} else {
		if *argRedisDB > 0 {
			cfg.RedisDB = *argRedisDB
		}
	}
	if val := os.Getenv("REDIS_USERNAME"); val != "" {
		cfg.RedisUsername = val
	} else {
		if *argRedisUsername != "" {
			cfg.RedisUsername = *argRedisUsername
		}
	}
	if val := os.Getenv("REDIS_PASSWORD"); val != "" {
		cfg.RedisPassword = val
	} else {
		if *argRedisPassword != "" {
			cfg.RedisPassword = *argRedisPassword
		}
	}

	if val := os.Getenv("REDIS_WRITER_ADDRESS"); val != "" {
		cfg.RedisAddressW = val
	} else {
		if *argRedisAddressW != "" {
			cfg.RedisAddressW = *argRedisAddressW
		}
	}
	if val := os.Getenv("REDIS_WRITER_PORT"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: REDIS_WRITER_PORT can not be used:", parser.Usage(err))
		}
		cfg.RedisPortW = p
	} else {
		if *argRedisPortW != 0 {
			cfg.RedisPortW = *argRedisPortW
		}
	}
	if val := os.Getenv("REDIS_WRITER_DATABASE_NUMBER"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: REDIS_WRITER_DATABASE_NUMBER can not be used:", parser.Usage(err))
		}
		cfg.RedisDBW = p
	} else {
		if *argRedisDBW > 0 {
			cfg.RedisDBW = *argRedisDBW
		}
	}
	if val := os.Getenv("REDIS_WRITER_USERNAME"); val != "" {
		cfg.RedisUsernameW = val
	} else {
		if *argRedisUsernameW != "" {
			cfg.RedisUsernameW = *argRedisUsernameW
		}
	}
	if val := os.Getenv("REDIS_WRITER_PASSWORD"); val != "" {
		cfg.RedisPasswordW = val
	} else {
		if *argRedisPasswordW != "" {
			cfg.RedisPasswordW = *argRedisPasswordW
		}
	}

	if val := os.Getenv("REDIS_PREFIX"); val != "" {
		cfg.RedisPrefix = val
	} else {
		if *argRedisPrefix != "" {
			cfg.RedisPrefix = *argRedisPrefix
		}
	}
	if val := os.Getenv("REDIS_TTL"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: REDIS_TTL can not be used:", parser.Usage(err))
		}
		cfg.RedisTTL = p
	} else {
		if *argRedisTTL != 0 {
			cfg.RedisTTL = *argRedisTTL
		}
	}

	if val := os.Getenv("GEOIP_PATH"); val != "" {
		cfg.GeoipPath = val
	} else {
		if *argGeoIPDB != "" {
			cfg.GeoipPath = *argGeoIPDB
		}
	}

	if val := os.Getenv("MAX_COUNTRIES"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: MAX_COUNTRIES can not be used:", parser.Usage(err))
		}
		cfg.MaxCountries = p
	} else {
		if *argMaxCountries != 0 {
			cfg.MaxCountries = *argMaxCountries
		}
	}
	if val := os.Getenv("MAX_IPS"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: MAX_IPS can not be used:", parser.Usage(err))
		}
		cfg.MaxIps = p
	} else {
		if *argMaxIps != 0 {
			cfg.MaxIps = *argMaxIps
		}
	}

	var wlFileName string

	if val := os.Getenv("WHITELIST_PATH"); val != "" {
		wlFileName = val
	} else {
		if *argWhiteList != "" {
			wlFileName = *argWhiteList
		}
	}

	if wlFileName != "" {
		jsonFile, err := os.Open(wlFileName)
		if err != nil {
			log.Fatalln("Error:", err)
		}

		//goland:noinspection GoUnhandledErrorResult
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)
		if err := json.Unmarshal(byteValue, &data); err != nil {
			log.Fatalln("Error:", err)
		}

		cfg.WhiteList = data
	}
}
