package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"log"
	"os"
	"strconv"
)

// Defaults
const serverAddress = "127.0.0.1"
const serverPort = 4646
const redisAddress = "127.0.0.1"
const redisPort = 6379
const geoipPath = "/usr/share/GeoIP/GeoLite2-City.mmdb"

// TODO: Make the following constants configurable
const redisPrefix = "geopol_"
const redisTTL = 3600
const maxCountries = 3
const maxIps = 10

type config struct {
	serverAddress string
	serverPort    int
	redisAddress  string
	redisPort     int
	geoipPath     string
	verbose		  bool
}

var cfg config

func initConfig(args []string) {
	parser := argparse.NewParser("geoip-policyd", "Detect compromised e-mail accounts")

	commandServer := parser.NewCommand("server", "Run a geoip policy server")

	argServerAddress := commandServer.String(
		"a", "server-address", &argparse.Options{
			Required: false,
			Help: "IPv4, IPv6 address or Unix-path for the policy service; default(" + serverAddress + ")",
		},
	)
	argServerPort := commandServer.String(
		"p", "server-port", &argparse.Options{
			Required: false,
			Help: "Port for the policy service; default(" + strconv.Itoa(serverPort) + ")",
		},
	)
	argRedisAddress := commandServer.String(
		"A", "redis-address", &argparse.Options{
			Required: false,
			Help: "IPv4, IPv6 address or Unix-path for the Redis service; default(" + redisAddress + ")",
		},
	)
	argRedisPort := commandServer.String(
		"P", "redis-port", &argparse.Options{
			Required: false,
			Help: "Port for the Redis service; default(" + strconv.Itoa(redisPort) + ")",
		},
	)
	argGeoIPDB := commandServer.String(
		"g", "geoip-path", &argparse.Options{
			Required: false,
			Help: "Full path to the GeoIP database file",
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

	cfg = config{
		serverAddress: serverAddress,
		serverPort: serverPort,
		redisAddress: redisAddress,
		redisPort: redisPort,
		geoipPath: geoipPath,
	}

	if *argVersion {
		fmt.Println("Version:", version)
		os.Exit(0)
	}

	cfg.verbose = *argVerbose

	if val := os.Getenv("SERVER_ADDRESS"); val != "" {
		cfg.serverAddress = val
	} else {
		if len(*argServerAddress) > 0 {
			cfg.serverAddress = *argServerAddress
		}
	}

	if val := os.Getenv("SERVER_PORT"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: SERVER_PORT an not be used:", parser.Usage(err))
		}
		cfg.serverPort = p
	} else {
		if len(*argServerPort) > 0 {
			p, err := strconv.Atoi(*argServerPort)
			if err != nil {
				log.Fatalln("Error: --server-port can not be used:", parser.Usage(err))
			}
			cfg.serverPort = p
		}
	}

	if val := os.Getenv("REDIS_ADDRESS"); val != "" {
		cfg.redisAddress = val
	} else {
		if len(*argRedisAddress) > 0 {
			cfg.redisAddress = *argRedisAddress
		}
	}

	if val := os.Getenv("REDIS_PORT"); val != "" {
		p, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalln("Error: REDIS_PORT can not be used:", parser.Usage(err))
		}
		cfg.redisPort = p
	} else {
		if len(*argRedisPort) > 0 {
			p, err := strconv.Atoi(*argRedisPort)
			if err != nil {
				log.Fatalln("Error: --redis-port can not be used", parser.Usage(err))
			}
			cfg.redisPort = p
		}
	}

	if val := os.Getenv("GEOIP_PATH"); val != "" {
		cfg.geoipPath = val
	} else {
		if len(*argGeoIPDB) > 0 {
			cfg.geoipPath = *argGeoIPDB
		}
	}
}
