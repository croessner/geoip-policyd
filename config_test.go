package main

import (
	"os"
	"testing"
)

func TestConfigVerboseNone(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server"})
	if cfg.Verbose != logLevelNone {
		t.Errorf("Expected --verbose not set, got value=%v", cfg.Verbose)
	}
}

func TestConfigVerboseInfo(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--verbose"})
	if cfg.Verbose != logLevelInfo {
		t.Errorf("Expected --verbose, got value=%v", cfg.Verbose)
	}
}

func TestConfigVerboseDebug(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--verbose", "--verbose"})
	if cfg.Verbose != logLevelDebug {
		t.Errorf("Expected --verbose --verbose, got value=%v", cfg.Verbose)
	}
}

func TestConfigServerAddress(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--server-address", "172.16.23.45"})
	if cfg.ServerAddress != "172.16.23.45" {
		t.Errorf("Expected --server-address=172.16.23.45, got value=%v", cfg.ServerAddress)
	}
}

func TestConfigServerPort(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--server-port", "9000"})
	if cfg.ServerPort != 9000 {
		t.Errorf("Expected --server-port=9000, got value=%v", cfg.ServerPort)
	}
}

func TestConfigHttpAddress(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--http-address", "192.168.0.1:80"})
	if cfg.HttpAddress != "192.168.0.1:80" {
		t.Errorf("Expected --http-address=192.168.0.1:80, got value=%v", cfg.HttpAddress)
	}
}

func TestConfigRedisAddress(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-address", "192.168.0.1"})
	if cfg.RedisAddress != "192.168.0.1" {
		t.Errorf("Expected --redis-address=192.168.0.1, got value=%v", cfg.RedisAddress)
	}
}

func TestConfigRedisPort(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-port", "6333"})
	if cfg.RedisPort != 6333 {
		t.Errorf("Expected --redis-port=6333, got value=%v", cfg.RedisPort)
	}
}

func TestConfigRedisDatabaseNumber(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-database-number", "4"})
	if cfg.RedisDB != 4 {
		t.Errorf("Expected --redis-database-number=4, got value=%v", cfg.RedisDB)
	}
}

func TestConfigRedisUsername(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-username", "username"})
	if cfg.RedisUsername != "username" {
		t.Errorf("Expected --redis-username=username, got value=%v", cfg.RedisUsername)
	}
}

func TestConfigRedisPassword(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-password", "password"})
	if cfg.RedisPassword != "password" {
		t.Errorf("Expected --redis-password=password, got value=%v", cfg.RedisPassword)
	}
}

func TestConfigRedisWriterAddress(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-writer-address", "192.168.0.1"})
	if cfg.RedisAddressW != "192.168.0.1" {
		t.Errorf("Expected --redis-writer-address=192.168.0.1, got value=%v", cfg.RedisAddressW)
	}
}

func TestConfigRedisWriterPort(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-writer-port", "6333"})
	if cfg.RedisPortW != 6333 {
		t.Errorf("Expected --redis-writer-port=6333, got value=%v", cfg.RedisPortW)
	}
}

func TestConfigRedisWriterDatabaseNumber(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-writer-database-number", "4"})
	if cfg.RedisDBW != 4 {
		t.Errorf("Expected --redis-writer-database-number=4, got value=%v", cfg.RedisDBW)
	}
}

func TestConfigRedisWriterUsername(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-writer-username", "username"})
	if cfg.RedisUsernameW != "username" {
		t.Errorf("Expected --redis-writer-username=username, got value=%v", cfg.RedisUsernameW)
	}
}

func TestConfigRedisWriterPassword(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-writer-password", "password"})
	if cfg.RedisPasswordW != "password" {
		t.Errorf("Expected --redis-writer-password=password, got value=%v", cfg.RedisPasswordW)
	}
}

func TestConfigRedisPrefix(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-prefix", "some_prefix_"})
	if cfg.RedisPrefix != "some_prefix_" {
		t.Errorf("Expected --redis-prefix=some_prefix_, got value=%v", cfg.RedisPrefix)
	}
}

func TestConfigRedisTTL(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--redis-ttl", "300"})
	if cfg.RedisTTL != 300 {
		t.Errorf("Expected --redis-ttl=300, got value=%v", cfg.RedisTTL)
	}
}

func TestConfigGeoipPath(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--geoip-path", "/tmp"})
	if cfg.GeoipPath != "/tmp" {
		t.Errorf("Expected --geoip-path=/tmp, got value=%v", cfg.GeoipPath)
	}
}

func TestConfigMaxCountries(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--max-countries", "10"})
	if cfg.MaxCountries != 10 {
		t.Errorf("Expected --max-countries=10, got value=%v", cfg.MaxCountries)
	}
}

func TestConfigMaxIPs(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--max-ips", "100"})
	if cfg.MaxIps != 100 {
		t.Errorf("Expected --max-ips=100, got value=%v", cfg.MaxIps)
	}
}

func TestConfigBlockedNoExpire(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--blocked-no-expire"})
	if cfg.BlockedNoExpire != true {
		t.Errorf("Expected --blocked-no-expire, got value=%v", cfg.BlockedNoExpire)
	}
}

func TestConfigCustomSettings(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--custom-settings-path", "/tmp"})
	if cfg.CustomSettingsPath != "/tmp" {
		t.Errorf("Expected --custom-settings-path=/tmp, got value=%v", cfg.CustomSettingsPath)
	}
}

func TestConfigHttpUseBasicAuth(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--http-use-basic-auth"})
	if cfg.HttpApp.UseBasicAuth != true {
		t.Errorf("Expected --http-use-basic-auth, got value=%v", cfg.HttpApp.UseBasicAuth)
	}
}

func TestConfigHttpBasicAuthUsername(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--http-basic-auth-username", "username"})
	if cfg.HttpApp.Auth.Username != "username" {
		t.Errorf("Expected --http-basic-auth-username=username, got value=%v", cfg.HttpApp.Auth.Username)
	}
}

func TestConfigHttpBasicAuthPassword(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--http-basic-auth-password", "password"})
	if cfg.HttpApp.Auth.Password != "password" {
		t.Errorf("Expected --http-basic-auth-password=password, got value=%v", cfg.HttpApp.Auth.Password)
	}
}

func TestConfigHttpUseSSL(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--http-use-ssl"})
	if cfg.HttpApp.UseSSL != true {
		t.Errorf("Expected --http-use-ssl, got value=%v", cfg.HttpApp.UseSSL)
	}
}

func TestConfigHttpTLSCert(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--http-tls-cert", "/tmp"})
	if cfg.HttpApp.X509.Cert != "/tmp" {
		t.Errorf("Expected --http-tls-cert=/tmp, got value=%v", cfg.HttpApp.X509.Cert)
	}
}

func TestConfigHttpTLSKey(t *testing.T) {
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server", "--http-tls-key", "/tmp"})
	if cfg.HttpApp.X509.Key != "/tmp" {
		t.Errorf("Expected --http-tls-key=/tmp, got value=%v", cfg.HttpApp.X509.Key)
	}
}

func TestConfigEnvVerboseNone(t *testing.T) {
	//goland:noinspection GoUnhandledErrorResult
	os.Setenv("VERBOSE", "none")
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server"})
	if cfg.Verbose != logLevelNone {
		t.Errorf("Expected VERBOSE=%d, got value=%v", logLevelNone, cfg.Verbose)
	}
}

func TestConfigEnvVerboseInfo(t *testing.T) {
	//goland:noinspection GoUnhandledErrorResult
	os.Setenv("VERBOSE", "info")
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server"})
	if cfg.Verbose != logLevelInfo {
		t.Errorf("Expected VERBOSE=%d, got value=%v", logLevelInfo, cfg.Verbose)
	}
}

func TestConfigEnvVerboseDebug(t *testing.T) {
	//goland:noinspection GoUnhandledErrorResult
	os.Setenv("VERBOSE", "debug")
	cfg := new(CmdLineConfig)
	cfg.Init([]string{"app", "server"})
	if cfg.Verbose != logLevelDebug {
		t.Errorf("Expected VERBOSE=%d, got value=%v", logLevelDebug, cfg.Verbose)
	}
}
