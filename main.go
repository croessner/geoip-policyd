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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
	"github.com/oschwald/maxminddb-golang"
)

const version = "@@gittag@@-@@gitcommit@@"

var (
	config              *CmdLineConfig         //nolint:gochecknoglobals // System wide configuration
	customSettingsStore atomic.Value           //nolint:gochecknoglobals // System wide configuration from custom.yml file
	geoIPStore          atomic.Value           //nolint:gochecknoglobals // System wide GeoIP handler
	ldapRequestChan     chan LdapRequest       //nolint:gochecknoglobals // Needed for LDAP pooling
	ldapEnd             chan bool              //nolint:gochecknoglobals // Quit-Channel for LDAP on shutdown
	redisHandle         redis.UniversalClient  //nolint:gochecknoglobals // System wide redis pool
	redisHandleReplica  redis.UniversalClient  //nolint:gochecknoglobals // System wide redis pool
	logger              log.Logger             //nolint:gochecknoglobals // System wide logger
	ctx                 = context.Background() //nolint:gochecknoglobals // System wide context
)

type RedisLogger struct{}

func (r *RedisLogger) Printf(_ context.Context, format string, values ...any) {
	level.Info(logger).Log("redis", fmt.Sprintf(format, values...))
}
func initCustomSettings(cmdLineConfig *CmdLineConfig) *CustomSettings {
	customSettings := &CustomSettings{}

	if cmdLineConfig.CustomSettingsPath != "" {
		jsonFile, err := os.Open(cmdLineConfig.CustomSettingsPath)
		if err != nil {
			level.Error(logger).Log("error", err.Error())
		}

		//goland:noinspection GoUnhandledErrorResult
		defer jsonFile.Close()

		if byteValue, err := io.ReadAll(jsonFile); err != nil {
			level.Error(logger).Log("error", err.Error())
		} else if err := json.Unmarshal(byteValue, customSettings); err != nil {
			level.Error(logger).Log("error", err.Error())
		}

		return customSettings
	}

	return nil
}

func NewRedisClient() redis.UniversalClient {
	var (
		redisAddresses          []string
		redisSentinelMasterName string
	)

	// If two or more sentinels are defined and a master name is set, switch to a FailoverClient.
	if len(config.RedisSentinels) > 1 && config.RedisSentinelMasterName != "" {
		redisAddresses = config.RedisSentinels
		redisSentinelMasterName = config.RedisSentinelMasterName

		redisHandle = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    redisSentinelMasterName,
			SentinelAddrs: redisAddresses,
		})
	} else {
		redisAddresses = []string{fmt.Sprintf("%s:%d", config.RedisAddress, config.RedisPort)}

		redisHandle = redis.NewClient(&redis.Options{
			Addr:     redisAddresses[0],
			Username: config.RedisUsername,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		})
	}

	return redisHandle
}

func NewRedisReplicaClient() redis.UniversalClient {
	if len(config.RedisSentinels) > 1 && config.RedisSentinelMasterName != "" {
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    config.RedisSentinelMasterName,
			SentinelAddrs: config.RedisSentinels,
			SlaveOnly:     true,
		})
	}

	if config.RedisAddressRO != config.RedisAddress || config.RedisPortRO != config.RedisPort {
		return redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", config.RedisAddressRO, config.RedisPortRO),
			Username: config.RedisUsernameRO,
			Password: config.RedisPasswordRO,
			DB:       config.RedisDBRO,
		})
	}

	return nil
}

func main() {
	var (
		err      error
		server   net.Listener
		logLevel level.Option
	)

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	config = &CmdLineConfig{}
	config.Init(os.Args)

	ioWriter := log.NewSyncWriter(os.Stdout)

	if config.LogFormatJSON {
		logger = log.NewJSONLogger(ioWriter)
	} else {
		logger = log.NewLogfmtLogger(ioWriter)
	}

	switch config.VerboseLevel {
	case logLevelNone:
		logLevel = level.AllowNone()
	case logLevelInfo:
		logLevel = level.AllowInfo()
	case logLevelDebug:
		logLevel = level.AllowDebug()
	}

	logger = level.NewFilter(logger, logLevel)

	if config.VerboseLevel == logLevelDebug {
		logger = log.With(logger, "ts", log.DefaultTimestamp, "caller", log.DefaultCaller)
	} else {
		logger = log.With(logger, "ts", log.DefaultTimestamp)
	}

	// Manually set time zone
	if tz := os.Getenv("TZ"); tz != "" {
		if time.Local, err = time.LoadLocation(tz); err != nil {
			level.Error(logger).Log("error", fmt.Sprintf("Error loading location '%s': %v", tz, err.Error()))
		}
	}

	go func() {
		sig := <-sigs

		level.Info(logger).Log("msg", "Shutting down geoip-policyd", "signal", sig)
		os.Exit(0)
	}()

	if config.CommandServer {
		customSettingsStore.Store(initCustomSettings(config))

		level.Info(logger).Log("msg", "Starting geoip-policyd", "version", version)

		if config.UseLDAP {
			ldapRequestChan = make(chan LdapRequest, ldapPoolSize)
			ldapEnd = make(chan bool)

			// Start LDAP worker process
			go ldapWorker()
		}

		geoIP := &GeoIP{}
		geoIP.Reader, err = maxminddb.Open(config.GeoipPath)

		if err != nil {
			level.Error(logger).Log("msg", "Can not open GeoLite2-City database file", "error", err.Error())

			geoIP = nil
		}

		geoIPStore.Store(geoIP)

		// REST interface
		go httpApp()

		redisLogger := &RedisLogger{}
		redis.SetLogger(redisLogger)

		redisHandle = NewRedisClient()
		redisHandleReplica = NewRedisReplicaClient()

		if redisHandleReplica == nil {
			redisHandleReplica = redisHandle
		}

		server, err = net.Listen("tcp", fmt.Sprintf("%s:%d", config.ServerAddress, config.ServerPort))
		if server == nil {
			level.Error(logger).Log("msg", "Unable to start server", "error", err.Error())
		}

		clientChan := clientConnections(server)

		for {
			go handleConnection(<-clientChan, config)
		}
	}
}
