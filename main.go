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
	"errors"
	"fmt"
	"io"
	stdLibLog "log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/oschwald/maxminddb-golang"
	"github.com/redis/go-redis/v9"
)

const version = "@@gittag@@-@@gitcommit@@"

var (
	config              *CmdLineConfig
	geoIP               *GeoIP
	customSettingsStore atomic.Value
	cdbStore            atomic.Value
	ldapRequestChan     chan *LdapRequest
	ldapEndChan         chan bool
	redisHandle         redis.UniversalClient
	redisHandleReplica  redis.UniversalClient
	logger              log.Logger
	ctx                 = context.Background()
)

type RedisLogger struct{}

func (r *RedisLogger) Printf(_ context.Context, format string, values ...any) {
	level.Info(logger).Log("redis", fmt.Sprintf(format, values...))
}

// initCustomSettings initializes the custom settings based on the provided command line configuration.
// If the CustomSettingsPath in the cmdLineConfig is non-empty, it reads the JSON file, unmarshals it into
// the customSettings object, and then flushes users from Redis based on the customSettings.
// Returns the initialized customSettings or nil if there is no custom settings path provided.
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

		flushUsersFromRedis(customSettings)

		return customSettings
	}

	return nil
}

// flushUsersFromRedis flushes user accounts from Redis based on the provided custom settings.
// If the customSettings object is nil or the settings.Data field is nil, the function does nothing.
// The function iterates over each account in settings.Data and deletes the corresponding key from Redis.
// It constructs the Redis key using the `Sender` field of the account and the RedisPrefix configuration.
// If an error occurs during the deletion, it checks if the error is due to the key not existing in Redis (redis.Nil),
// in which case it returns immediately.
// Otherwise, it logs the error using the provided logger.
func flushUsersFromRedis(settings *CustomSettings) {
	if settings.Data == nil {
		return
	}

	for _, account := range settings.Data {
		err := redisHandle.Del(context.TODO(), fmt.Sprintf("%s%s", config.RedisPrefix, account.Sender)).Err()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return
			}

			level.Error(logger).Log("error", err.Error())
		}
	}
}

// createFailoverClient creates a Redis failover client based on the provided configuration.
// It takes a boolean parameter `replicaOnly` to determine whether to connect to replica nodes only.
// It uses the `redis.FailoverOptions` struct to configure the client's settings, such as master name, sentinel addresses, etc.
// It returns a `redis.UniversalClient` instance.
func createFailoverClient(replicaOnly bool) redis.UniversalClient {
	return redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       config.RedisSentinelMasterName,
		SentinelAddrs:    config.RedisSentinels,
		ReplicaOnly:      replicaOnly,
		DB:               config.RedisDB,
		SentinelUsername: config.RedisSentinelUsername,
		SentinelPassword: config.RedisSentinelPassword,
		Username:         config.RedisUsername,
		Password:         config.RedisPassword,
	})
}

// createStandardClient creates a Redis client with standard configuration.
// It takes a string parameter `addr` to specify the address of the Redis server.
// It takes an int parameter `port` to specify the port number of the Redis server.
// It uses the `redis.Options` struct to configure the client's settings, such as address, username, password, etc.
// It returns a `redis.UniversalClient` instance.
func createStandardClient(addr string, port int) redis.UniversalClient {
	return redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", addr, port),
		Username: config.RedisUsername,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})
}

// NewRedisClient creates a Redis client based on the provided configuration.
// If Redis sentinels and a master name are defined in the configuration,
// it creates a failover client using the createFailoverClient function.
// Otherwise, it creates a standard client using the createStandardClient function.
// It returns a redis.UniversalClient instance.
func NewRedisClient() redis.UniversalClient {
	if len(config.RedisSentinels) > 0 && config.RedisSentinelMasterName != "" {
		redisHandle = createFailoverClient(false)
	} else {
		redisHandle = createStandardClient(config.RedisAddress, config.RedisPort)
	}

	return redisHandle
}

// NewRedisReplicaClient returns a Redis replica client based on the provided configuration.
// If Redis sentinels and a master name are defined in the configuration, it creates a failover client using the createFailoverClient function.
// Otherwise, it creates a standard client using the createStandardClient function.
// It returns a redis.UniversalClient instance or nil if no configuration is provided.
func NewRedisReplicaClient() redis.UniversalClient {
	if len(config.RedisSentinels) > 0 && config.RedisSentinelMasterName != "" {
		return createFailoverClient(true)
	}

	if config.RedisAddressRO != config.RedisAddress || config.RedisPortRO != config.RedisPort {
		return createStandardClient(config.RedisAddressRO, config.RedisPortRO)
	}

	return nil
}

// initializeSignalHandler initializes a signal handler that listens for OS signals
// SIGINT and SIGTERM. It returns a channel that receives the signals.
//
// The returned channel can be used to wait for and handle the signals in code.
// This function should be called at the start of a program to set up signal handling.
//
// Example usage:
// sigs := initializeSignalHandler()
// go waitForShutdownSignal(sigs)
//
// The `waitForShutdownSignal` function will block until a signal is received,
// and then exit the program gracefully.
//
// Dependencies: "os", "os/signal", "syscall".
//
// Returns: A channel of type os.Signal.
func initializeSignalHandler() chan os.Signal {
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	return sigs
}

// initializeLogger initializes the logger based on the configuration settings. It creates a new logger using
// log.NewSyncWriter and os.Stdout as the output. Depending on the value of config.LogFormatJSON, it creates a
// logger of type log.Logger using either log.NewJSONLogger or log.NewLogfmtLogger as the formatter. It then
// creates a logLevelOpt level.Option based on the value of config.VerboseLevel. The logger is then filtered
// using level.NewFilter with the logLevelOpt. If config.VerboseLevel is logLevelDebug, additional context
// fields "ts" and "caller" are added using log.With. Finally, the logger is set as the output for stdLibLog
// using log.NewStdlibAdapter.
//
// Dependencies: "os", "github.com/go-kit/kit/log"
//
// Variables:
// - ioWriter:     Initialized with log.NewSyncWriter(os.Stdout)
// - logger:       log.Logger
// - logLevelOpt:  level.Option
//
// Returns: None
func initializeLogger() {
	ioWriter := log.NewSyncWriter(os.Stdout)

	if config.LogFormatJSON {
		logger = log.NewJSONLogger(ioWriter)
	} else {
		logger = log.NewLogfmtLogger(ioWriter)
	}

	var logLevelOpt level.Option

	switch config.VerboseLevel {
	case logLevelNone:
		logLevelOpt = level.AllowNone()
	case logLevelInfo:
		logLevelOpt = level.AllowInfo()
	case logLevelDebug:
		logLevelOpt = level.AllowDebug()
	}

	logger = level.NewFilter(logger, logLevelOpt)

	if config.VerboseLevel == logLevelDebug {
		logger = log.With(logger, "ts", log.DefaultTimestamp, "caller", log.DefaultCaller)
	} else {
		logger = log.With(logger, "ts", log.DefaultTimestamp)
	}

	stdLibLog.SetOutput(log.NewStdlibAdapter(logger))
}

// setTimeZone sets the local timezone based on the value of the "TZ" environment variable.
// If the "TZ" environment variable is set, it attempts to load the timezone using time.LoadLocation.
// If the loading is successful, it sets the local timezone to the loaded timezone.
// If the loading fails, it logs an error message using the provided logger.
// This function should be called at the start of the program to set the local timezone.
// Dependencies: "os", "time".
// Returns: None.
func setTimeZone() {
	if tz := os.Getenv("TZ"); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			level.Error(logger).Log("error", fmt.Sprintf("Error loading location '%s': %v", tz, err.Error()))
		} else {
			time.Local = loc
		}
	}
}

// waitForShutdownSignal waits for a signal to be received on the `sigs` channel
// and logs a shutdown message with the received signal. Once a signal is received,
// the function exits the program with an exit code of 0.
//
// Dependencies: "os", "log"
//
// Variables:
// - sig:     The signal received from the channel
//
// Returns: None
func waitForShutdownSignal(sigs chan os.Signal) {
	sig := <-sigs

	level.Info(logger).Log("msg", "Shutting down geoip-policyd", "signal", sig)

	os.Exit(0)
}

// configureRedis initializes and configures the Redis clients and logger for the geoip-policyd application.
// It takes a RedisLogger pointer as a parameter and sets it as the logger for the Redis client.
// It then creates the primary Redis client using the NewRedisClient function, and assigns it to the redisHandle variable.
// If the replica client is not configured, it assigns the primary client to the redisHandleReplica variable.
// It then initializes the custom settings using the initCustomSettings function and stores the result in the customSettingsStore.
// Finally, it logs the message "Starting geoip-policyd" with the current version.
func configureRedis(redisLogger *RedisLogger) {
	redis.SetLogger(redisLogger)

	redisHandle = NewRedisClient()
	redisHandleReplica = NewRedisReplicaClient()

	if redisHandleReplica == nil {
		redisHandleReplica = redisHandle
	}

	customSettingsStore.Store(initCustomSettings(config))
	level.Info(logger).Log("msg", "Starting geoip-policyd", "version", version)
}

// setupGeoIP initializes the GeoIP database reader by opening the specified GeoIP database file.
// It checks if the file exists and returns an error if it doesn't.
// If the file exists, it creates a new GeoIP instance and assigns the opened reader to its Reader field.
// It then starts a goroutine to automatically reload the GeoIP database if it is modified.
// Returns an error if there's an error opening the GeoIP database file.
func setupGeoIP() error {
	if _, err := os.Stat(config.GeoipPath); os.IsNotExist(err) {
		return fmt.Errorf("file '%s' does not exist", config.GeoipPath)
	} else if err != nil {
		return fmt.Errorf("file '%s' may exist, but there's an error accessing it", config.GeoipPath)
	}

	geoIP = &GeoIP{}

	var err error

	geoIP.Reader, err = maxminddb.Open(config.GeoipPath)
	if err != nil {
		return err
	}

	go autoReloadGeoIP(geoIP)

	return nil
}

// startLDAPWorker initializes and starts the LDAP worker goroutine.
// It creates the ldapRequestChan and ldapEndChan channels, and then calls the ldapWorker function in a new goroutine.
// The ldapRequestChan channel is used to receive LDAP requests, while the ldapEndChan channel is used to signal the termination of the ldapWorker goroutine.
func startLDAPWorker() {
	ldapRequestChan = make(chan *LdapRequest, ldapPoolSize)
	ldapEndChan = make(chan bool)

	go ldapWorker(context.Background())
}

// startServer starts the TCP server, listens for client connections, and handles each connection concurrently.
// It initializes the server using the configuration values and launches the HTTP server in a goroutine.
// Each client connection is handled concurrently by the handleConnection function.
// If an error occurs while starting the server, it logs the error and exits the program.
func startServer() {
	server, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ServerAddress, config.ServerPort))
	if err != nil {
		handleFileError("Unable to start server", err)
		return
	}

	clientChan := clientConnections(server)

	go httpApp()

	for {
		go handleConnection(<-clientChan)
	}
}

// startCommandServer starts the command server for the geoip-policyd application.
// It initializes the Redis logger, configures Redis, sets up the GeoIP database,
// starts the LDAP worker (if configured), initializes and stores the CDB (if configured),
// and starts the TCP server.
func startCommandServer() {
	redisLogger := &RedisLogger{}
	configureRedis(redisLogger)

	if err := setupGeoIP(); err != nil {
		handleFileError("Unable to open GeoLite2-City database file", err)
	}

	if config.UseLDAP {
		startLDAPWorker()
	}

	if config.UseCDB {
		cdbStore.Store(initializeCDB(config.CDBPath))
	}

	startServer()
}

// handleFileError logs an error message and panics with the provided error message.
// It logs the message and the error using the logger at the Error level.
// It then panics with the error message as the argument.
//
// The function is typically used to handle file-related errors in the application.
// In the provided usage examples, it is used to handle errors during server startup and database initialization.
// After logging the error, it exits the program with an error code.
// The function does not return any value.
// It takes two parameters: a message string and an error.
// The message string is a description of the error and is used for logging purposes.
// The error is the actual error that occurred.
//
// The function is not meant to be used directly as it causes a panic.
// Instead, it is typically called within a context where the panic can be recovered,
// such as within a defer statement or a separate goroutine.
//
// The function assumes the presence of a logger variable of type log.Logger,
// which is used to log the error message.
//
// The function does not provide an example of usage as it is typically used internally in the application.
func handleFileError(msg string, err error) {
	level.Error(logger).Log("msg", msg, "error", err.Error())

	panic(err.Error())
}

// initializeCDB initializes and opens a CDB file at the specified path.
// If an error occurs while opening the CDB file, it logs the error and returns nil.
// Otherwise, it returns the opened CDB file.
func initializeCDB(cdbPath string) *cdb.CDB {
	db, err := cdb.Open(cdbPath)
	if err != nil {
		level.Error(logger).Log("msg", "Unable to open CDB file", "error", err.Error())

		return nil
	}

	return db
}

// autoReloadGeoIP continuously checks for changes in the GeoIP database file.
// When a change is detected, it closes the existing reader and opens a new one.
// The function takes a pointer to a `GeoIP` struct as an argument.
// The `GeoIP` struct contains a `Reader` field which is an instance of `maxminddb.Reader`.
// The function uses a ticker to run every 300 seconds (5 minutes).
// If there's an error getting the file info, it logs the error and continues to the next iteration.
// If the modified time of the file is different from the last checked modified time,
// it logs that the GeoIP database file has changed and proceeds to update the `Reader`.
// Before updating the `Reader`, it acquires a lock on the `mu` mutex to prevent concurrent access.
// It closes the existing `Reader` and attempts to open a new `Reader` using the file path specified in the configuration.
// If there's an error opening the file, it logs the error and assigns `nil` to the `Reader` field of the `GeoIP` struct.
// Finally, it releases the lock and continues to the next iteration in the ticker.
func autoReloadGeoIP(geoIP *GeoIP) {
	var lastModTime time.Time

	ticker := time.NewTicker(300 * time.Second)
	for range ticker.C {
		fileInfo, err := os.Stat(config.GeoipPath)

		if err != nil {
			level.Error(logger).Log("msg", "Unable to get file info", "error", err.Error())

			continue
		}

		if !fileInfo.ModTime().Equal(lastModTime) {
			level.Info(logger).Log("msg", "GeoIP database file has changed")

			lastModTime = fileInfo.ModTime()

			geoIP.mu.Lock()
			geoIP.Reader.Close()

			geoIP.Reader, err = maxminddb.Open(config.GeoipPath)
			if err != nil {
				level.Error(logger).Log("msg", "Unable to open GeoLite2-City database file", "error", err.Error())
				geoIP.Reader = nil
			}

			geoIP.mu.Unlock()
		}
	}
}

func main() {
	sigs := initializeSignalHandler()

	config = &CmdLineConfig{}

	config.Init(os.Args)

	initializeLogger()
	setTimeZone()

	go waitForShutdownSignal(sigs)

	if config.CommandServer {
		startCommandServer()
	}
}
