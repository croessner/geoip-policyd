// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
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

var version = "dev"

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
)

type RedisLogger struct {
	logger log.Logger
}

func NewRedisLogger(logger log.Logger) *RedisLogger {
	return &RedisLogger{logger: logger}
}

func (r *RedisLogger) Printf(_ context.Context, format string, values ...any) {
	_ = level.Info(r.logger).Log("redis", fmt.Sprintf(format, values...))
}

type RedisClientFactory struct {
	config *CmdLineConfig
}

func NewRedisClientFactory(config *CmdLineConfig) *RedisClientFactory {
	return &RedisClientFactory{config: config}
}

func (f *RedisClientFactory) Primary() redis.UniversalClient {
	if f.hasFailover() {
		return f.failover(false)
	}

	return f.standard(f.config.RedisAddress, f.config.RedisPort)
}

func (f *RedisClientFactory) Replica() redis.UniversalClient {
	if f.hasFailover() {
		return f.failover(true)
	}

	if f.config.RedisAddressRO != f.config.RedisAddress || f.config.RedisPortRO != f.config.RedisPort {
		return f.standard(f.config.RedisAddressRO, f.config.RedisPortRO)
	}

	return nil
}

func (f *RedisClientFactory) hasFailover() bool {
	return len(f.config.RedisSentinels) > 0 && f.config.RedisSentinelMasterName != ""
}

func (f *RedisClientFactory) failover(replicaOnly bool) redis.UniversalClient {
	return redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       f.config.RedisSentinelMasterName,
		SentinelAddrs:    f.config.RedisSentinels,
		ReplicaOnly:      replicaOnly,
		DB:               f.config.RedisDB,
		SentinelUsername: f.config.RedisSentinelUsername,
		SentinelPassword: f.config.RedisSentinelPassword,
		Username:         f.config.RedisUsername,
		Password:         f.config.RedisPassword,
	})
}

func (f *RedisClientFactory) standard(addr string, port int) redis.UniversalClient {
	return redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", addr, port),
		Username: f.config.RedisUsername,
		Password: f.config.RedisPassword,
		DB:       f.config.RedisDB,
	})
}

type CustomSettingsService struct {
	config *CmdLineConfig
	logger log.Logger
	redis  redis.UniversalClient
}

func NewCustomSettingsService(config *CmdLineConfig, redis redis.UniversalClient, logger log.Logger) *CustomSettingsService {
	return &CustomSettingsService{
		config: config,
		logger: logger,
		redis:  redis,
	}
}

// Load reads configured custom settings and flushes affected Redis entries with the supplied context.
func (s *CustomSettingsService) Load(ctx context.Context) *CustomSettings {
	customSettings := &CustomSettings{}

	if s.config.CustomSettingsPath == "" {
		return nil
	}

	jsonFile, err := os.Open(s.config.CustomSettingsPath)
	if err != nil {
		_ = level.Error(s.logger).Log("error", err.Error())

		return nil
	}

	//goland:noinspection GoUnhandledErrorResult
	defer func() {
		if err := jsonFile.Close(); err != nil {
			_ = level.Error(s.logger).Log("error", err.Error())
		}
	}()

	if byteValue, err := io.ReadAll(jsonFile); err != nil {
		_ = level.Error(s.logger).Log("error", err.Error())
	} else if err := json.Unmarshal(byteValue, customSettings); err != nil {
		_ = level.Error(s.logger).Log("error", err.Error())
	}

	s.FlushUsers(ctx, customSettings)

	return customSettings
}

// FlushUsers deletes Redis cache entries for all accounts touched by custom settings.
func (s *CustomSettingsService) FlushUsers(ctx context.Context, settings *CustomSettings) {
	if settings == nil || settings.Data == nil {
		return
	}

	if ctx == nil {
		ctx = context.Background()
	}

	for _, account := range settings.Data {
		err := s.redis.Del(ctx, fmt.Sprintf("%s%s", s.config.RedisPrefix, account.Sender)).Err()
		if err != nil && !errors.Is(err, redis.Nil) {
			_ = level.Error(s.logger).Log("error", err.Error())
		}
	}
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
			_ = level.Error(logger).Log("error", fmt.Sprintf("Error loading location '%s': %v", tz, err.Error()))
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

	_ = level.Info(logger).Log("msg", "Shutting down geoip-policyd", "signal", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if obs := currentObservability(); obs != nil {
		if err := obs.Shutdown(shutdownCtx); err != nil {
			_ = level.Error(logger).Log("msg", "Unable to flush observability providers", "error", err.Error())
		}
	}

	os.Exit(0)
}

// configureRedis initializes and configures the Redis clients and logger for the geoip-policyd application.
// It takes a RedisLogger pointer as a parameter and sets it as the logger for the Redis client.
func configureRedis(redisLogger *RedisLogger) {
	redis.SetLogger(redisLogger)

	redisFactory := NewRedisClientFactory(config)
	redisHandle = redisFactory.Primary()
	redisHandleReplica = redisFactory.Replica()

	if redisHandleReplica == nil {
		redisHandleReplica = redisHandle
	}

	if obs := currentObservability(); obs != nil {
		obs.InstrumentRedisClient(redisHandle, "primary")

		if redisHandleReplica != redisHandle {
			obs.InstrumentRedisClient(redisHandleReplica, "replica")
		}
	}

	customSettingsService := NewCustomSettingsService(config, redisHandle, logger)
	storeCustomSettings(customSettingsService.Load(context.Background()))

	_ = level.Info(logger).Log("msg", "Starting geoip-policyd", "version", version)
}

// initializeObservability builds the configured metrics and tracing runtime.
func initializeObservability() error {
	observabilityRuntime, err := NewObservability(context.Background(), config.Observability, version, logger)
	if err != nil {
		return err
	}

	config.observabilityRuntime = observabilityRuntime

	return nil
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

	reader, err := maxminddb.Open(config.GeoipPath)
	if err != nil {
		return err
	}

	geoIP = NewGeoIP(reader)

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

// ListenerRuntime owns startup for the policy and HTTP listener pair.
type ListenerRuntime struct {
	config *CmdLineConfig
	logger log.Logger
}

// NewListenerRuntime creates a listener runtime from validated process configuration.
func NewListenerRuntime(config *CmdLineConfig, logger log.Logger) *ListenerRuntime {
	return &ListenerRuntime{
		config: config,
		logger: logger,
	}
}

// Start launches all enabled listeners and blocks until the active foreground listener stops.
func (r *ListenerRuntime) Start() {
	switch {
	case r.config.PolicyServiceEnabled():
		r.startPolicyServer()
	case r.config.HTTPServiceEnabled():
		_ = level.Info(r.logger).Log("msg", "Skipping geoip-policyd policy service", "reason", "policy service disabled")

		httpApp()
	default:
		handleFileError("Unable to start server", errors.New("at least one listener must be enabled"))
	}
}

// startPolicyServer listens for policy TCP clients and optionally starts HTTP in the background.
func (r *ListenerRuntime) startPolicyServer() {
	server, err := net.Listen("tcp", fmt.Sprintf("%s:%d", r.config.ServerAddress, r.config.ServerPort))
	if err != nil {
		handleFileError("Unable to start server", err)
		return
	}

	_ = level.Info(r.logger).Log("msg", "Starting geoip-policyd policy service", "address", server.Addr().String())

	clientChan := clientConnections(server)

	if r.config.HTTPServiceEnabled() {
		go httpApp()
	} else {
		_ = level.Info(r.logger).Log("msg", "Skipping geoip-policyd HTTP service", "reason", "HTTP service disabled")
	}

	for {
		go handleConnection(<-clientChan)
	}
}

// startServer creates the listener runtime and starts the configured services.
func startServer() {
	NewListenerRuntime(config, logger).Start()
}

// startCommandServer starts the command server for the geoip-policyd application.
// It initializes the Redis logger, configures Redis, sets up the GeoIP database,
// starts the LDAP worker (if configured), initializes and stores the CDB (if configured),
// and starts the TCP server.
func startCommandServer() {
	redisLogger := NewRedisLogger(logger)
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

// handleFileError logs a fatal startup error and terminates without emitting a panic stack trace.
func handleFileError(msg string, err error) {
	_ = level.Error(logger).Log("msg", msg, "error", err.Error())

	os.Exit(1)
}

// initializeCDB initializes and opens a CDB file at the specified path.
// If an error occurs while opening the CDB file, it logs the error and returns nil.
// Otherwise, it returns the opened CDB file.
func initializeCDB(cdbPath string) *cdb.CDB {
	db, err := cdb.Open(cdbPath)
	if err != nil {
		_ = level.Error(logger).Log("msg", "Unable to open CDB file", "error", err.Error())

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
			if obs := currentObservability(); obs != nil {
				obs.ObserveGeoIPReload(context.Background(), resultStatError)
			}

			_ = level.Error(logger).Log("msg", "Unable to get file info", "error", err.Error())

			continue
		}

		if !fileInfo.ModTime().Equal(lastModTime) {
			_ = level.Info(logger).Log("msg", "GeoIP database file has changed")

			lastModTime = fileInfo.ModTime()

			reader, err := maxminddb.Open(config.GeoipPath)
			if err != nil {
				if obs := currentObservability(); obs != nil {
					obs.ObserveGeoIPReload(context.Background(), resultError)
				}

				_ = level.Error(logger).Log("msg", "Unable to open GeoLite2-City database file", "error", err.Error())

				geoIP.SwapReader(nil)
			} else {
				if obs := currentObservability(); obs != nil {
					obs.ObserveGeoIPReload(context.Background(), resultOK)
				}

				geoIP.SwapReader(reader)
			}
		}
	}
}

func main() {
	sigs := initializeSignalHandler()

	config = &CmdLineConfig{}

	config.Init(os.Args)

	if config.CommandServer {
		if err := config.Validate(); err != nil {
			stdLibLog.Fatalln(err)
		}
	}

	initializeLogger()
	setTimeZone()

	if config.CommandServer {
		if err := initializeObservability(); err != nil {
			stdLibLog.Fatalln(err)
		}
	}

	go waitForShutdownSignal(sigs)

	if config.CommandServer {
		startCommandServer()
	}
}
