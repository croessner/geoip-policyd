package main

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"os"
	"testing"
)

func envSetter(envs map[string]string) (closer func()) {
	originalEnvs := map[string]string{}

	for name, value := range envs {
		if originalValue, ok := os.LookupEnv(name); ok {
			originalEnvs[name] = originalValue
		}

		_ = os.Setenv(name, value)
	}

	return func() {
		for name := range envs {
			origValue, has := originalEnvs[name]
			if has {
				_ = os.Setenv(name, origValue)
			} else {
				_ = os.Unsetenv(name)
			}
		}
	}
}

func TestConfigVerboseNone(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.VerboseLevel != logLevelNone {
		t.Errorf("Expected --verbose not set, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigEnvVerboseNone(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_VERBOSE_LEVEL": "none",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.VerboseLevel != logLevelNone {
		t.Errorf("Expected --verbose not set, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigVerboseInfo(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--verbose"})

	if cfg.VerboseLevel != logLevelInfo {
		t.Errorf("Expected --verbose, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigEnvVerboseInfo(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_VERBOSE_LEVEL": "info",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.VerboseLevel != logLevelInfo {
		t.Errorf("Expected --verbose, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigVerboseDebug(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--verbose", "--verbose"})

	if cfg.VerboseLevel != logLevelDebug {
		t.Errorf("Expected --verbose --verbose, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigEnvVerboseDebug(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_VERBOSE_LEVEL": "debug",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.VerboseLevel != logLevelDebug {
		t.Errorf("Expected --verbose --verbose, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigServerAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--server-address", "172.16.23.45"})

	if cfg.ServerAddress != "172.16.23.45" {
		t.Errorf("Expected --server-address=172.16.23.45, got value=%v", cfg.ServerAddress)
	}
}

func TestConfigEnvServerAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_SERVER_ADDRESS": "172.16.23.45",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.ServerAddress != "172.16.23.45" {
		t.Errorf("Expected --server-address=172.16.23.45, got value=%v", cfg.ServerAddress)
	}
}

func TestConfigServerPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--server-port", "9000"})

	if cfg.ServerPort != 9000 {
		t.Errorf("Expected --server-port=9000, got value=%v", cfg.ServerPort)
	}
}

func TestConfigEnvServerPort(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_SERVER_PORT": "9000",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.ServerPort != 9000 {
		t.Errorf("Expected --server-port=9000, got value=%v", cfg.ServerPort)
	}
}

func TestConfigUseSASLUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--sasl-username"})

	if cfg.UseSASLUsername != true {
		t.Errorf("Expected --sasl-username, got value=%v", cfg.UseSASLUsername)
	}
}

func TestConfigEnvUseSASLUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_SASL_USERNAME": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.UseSASLUsername != true {
		t.Errorf("Expected --sasl-username, got value=%v", cfg.ServerPort)
	}
}

func TestConfigHTTPAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--http-address", "192.168.0.1"})

	if cfg.HTTPAddress != "192.168.0.1" {
		t.Errorf("Expected --http-address=192.168.0.1, got value=%v", cfg.HTTPAddress)
	}
}

func TestConfigHTTPPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--http-port", "80"})

	if cfg.HTTPPort != 80 {
		t.Errorf("Expected --http-port=80, got value=%v", cfg.HTTPPort)
	}
}

func TestConfigEnvHTTPAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_ADDRESS": "192.168.0.1",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.HTTPAddress != "192.168.0.1" {
		t.Errorf("Expected --http-address=192.168.0.1, got value=%v", cfg.HTTPAddress)
	}
}

func TestConfigEnvHTTPPort(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_PORT": "80",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.HTTPPort != 80 {
		t.Errorf("Expected --http-port=80, got value=%v", cfg.HTTPPort)
	}
}

func TestConfigRedisAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-address", "192.168.0.1"})

	if cfg.RedisAddress != "192.168.0.1" {
		t.Errorf("Expected --redis-address=192.168.0.1, got value=%v", cfg.RedisAddress)
	}
}

func TestConfigEnvRedisAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_ADDRESS": "192.168.0.1",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisAddress != "192.168.0.1" {
		t.Errorf("Expected --redis-address=192.168.0.1, got value=%v", cfg.RedisAddress)
	}
}

func TestConfigRedisPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-port", "6333"})

	if cfg.RedisPort != 6333 {
		t.Errorf("Expected --redis-port=6333, got value=%v", cfg.RedisPort)
	}
}

func TestConfigEnvRedisPort(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_PORT": "6333",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisPort != 6333 {
		t.Errorf("Expected --redis-port=6333, got value=%v", cfg.RedisPort)
	}
}

func TestConfigRedisDatabaseNumber(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-database-number", "4"})

	if cfg.RedisDB != 4 {
		t.Errorf("Expected --redis-database-number=4, got value=%v", cfg.RedisDB)
	}
}

func TestConfigEnvRedisDatabaseNumber(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_DATABASE_NUMBER": "4",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisDB != 4 {
		t.Errorf("Expected --redis-database-number=4, got value=%v", cfg.RedisDB)
	}
}

func TestConfigRedisUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-username", "username"})

	if cfg.RedisUsername != "username" {
		t.Errorf("Expected --redis-username=username, got value=%v", cfg.RedisUsername)
	}
}

func TestConfigEnvRedisUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_USERNAME": "username",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisUsername != "username" {
		t.Errorf("Expected --redis-username=username, got value=%v", cfg.RedisUsername)
	}
}

func TestConfigRedisPassword(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-password", "password"})

	if cfg.RedisPassword != "password" {
		t.Errorf("Expected --redis-password=password, got value=%v", cfg.RedisPassword)
	}
}

func TestConfigEnvRedisPassword(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_PASSWORD": "password",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisPassword != "password" {
		t.Errorf("Expected --redis-password=password, got value=%v", cfg.RedisPassword)
	}
}

func TestConfigRedisReplicaAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-replica-address", "192.168.0.1"})

	if cfg.RedisAddressRO != "192.168.0.1" {
		t.Errorf("Expected --redis-replica-address=192.168.0.1, got value=%v", cfg.RedisAddressRO)
	}
}

func TestConfigEnvRedisReplicaAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_REPLICA_ADDRESS": "192.168.0.1",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisAddressRO != "192.168.0.1" {
		t.Errorf("Expected --redis-replica-address=192.168.0.1, got value=%v", cfg.RedisAddressRO)
	}
}

func TestConfigRedisReplicaPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-replica-port", "6333"})

	if cfg.RedisPortRO != 6333 {
		t.Errorf("Expected --redis-replica-port=6333, got value=%v", cfg.RedisPortRO)
	}
}

func TestConfigEnvRedisReplicaPort(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_REPLICA_PORT": "6333",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisPortRO != 6333 {
		t.Errorf("Expected --redis-replica-port=6333, got value=%v", cfg.RedisPortRO)
	}
}

func TestConfigRedisReplicaDatabaseNumber(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-replica-database-number", "4"})

	if cfg.RedisDBRO != 4 {
		t.Errorf("Expected --redis-replica-database-number=4, got value=%v", cfg.RedisDBRO)
	}
}

func TestConfigEnvRedisReplicaDatabaseNumber(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_REPLICA_DATABASE_NUMBER": "4",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisDBRO != 4 {
		t.Errorf("Expected --redis-replica-database-number=4, got value=%v", cfg.RedisDBRO)
	}
}

func TestConfigRedisReplicaUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-replica-username", "username"})

	if cfg.RedisUsernameRO != "username" {
		t.Errorf("Expected --redis-replica-username=username, got value=%v", cfg.RedisUsernameRO)
	}
}

func TestConfigEnvRedisReplicaUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_REPLICA_USERNAME": "username",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisUsernameRO != "username" {
		t.Errorf("Expected --redis-replica-username=username, got value=%v", cfg.RedisUsernameRO)
	}
}

func TestConfigRedisReplicaPassword(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-replica-password", "password"})

	if cfg.RedisPasswordRO != "password" {
		t.Errorf("Expected --redis-replica-password=password, got value=%v", cfg.RedisPasswordRO)
	}
}

func TestConfigEnvRedisReplicaPassword(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_REPLICA_PASSWORD": "password",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisPasswordRO != "password" {
		t.Errorf("Expected --redis-replica-password=password, got value=%v", cfg.RedisPasswordRO)
	}
}

func TestConfigRedisSentinels(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-sentinels", "10.0.0.1:26379", "--redis-sentinels", "10.0.0.2:26379"})

	if cfg.RedisSentinels[0] != "10.0.0.1:26379" && cfg.RedisSentinels[1] != "10.0.0.2:26379" {
		t.Errorf("Expected --redis-sentinels='10.0.0.1:26379 10.0.0.2:26379', got value=%v", cfg.RedisSentinels)
	}
}

func TestConfigEnvRedisSentinels(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_SENTINELS": "10.0.0.1:26379 10.0.0.2:26379",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisSentinels[0] != "10.0.0.1:26379" && cfg.RedisSentinels[1] != "10.0.0.2:26379" {
		t.Errorf("Expected --redis-sentinels='10.0.0.1:26379 10.0.0.2:26379', got value=%v", cfg.RedisSentinels)
	}
}

func TestConfigRedisSentinelMasterName(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-sentinel-master-name", "mymaster"})

	if cfg.RedisSentinelMasterName != "mymaster" {
		t.Errorf("Expected --redis-sentinel-master-name=mymaster, got value=%v", cfg.RedisSentinelMasterName)
	}
}

func TestConfigEnvRedisSentinelMasterName(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_SENTINEL_MASTER_NAME": "mymaster",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisSentinelMasterName != "mymaster" {
		t.Errorf("Expected --redis-sentinel-master-name=mymaster, got value=%v", cfg.RedisSentinelMasterName)
	}
}

func TestConfigRedisPrefix(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-prefix", "some_prefix_"})

	if cfg.RedisPrefix != "some_prefix_" {
		t.Errorf("Expected --redis-prefix=some_prefix_, got value=%v", cfg.RedisPrefix)
	}
}

func TestConfigEnvRedisPrefix(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_PREFIX": "some_prefix_",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisPrefix != "some_prefix_" {
		t.Errorf("Expected --redis-prefix=some_prefix_, got value=%v", cfg.RedisPrefix)
	}
}

func TestConfigRedisTTL(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--redis-ttl", "300"})

	if cfg.RedisTTL != 300 {
		t.Errorf("Expected --redis-ttl=300, got value=%v", cfg.RedisTTL)
	}
}

func TestConfigEnvRedisTTL(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_TTL": "300",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RedisTTL != 300 {
		t.Errorf("Expected --redis-ttl=300, got value=%v", cfg.RedisTTL)
	}
}

func TestConfigGeoIPPath(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--geoip-path", "/tmp"})

	if cfg.GeoipPath != "/tmp" {
		t.Errorf("Expected --geoip-path=/tmp, got value=%v", cfg.GeoipPath)
	}
}

func TestConfigEnvGeoIPPath(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_GEOIP_PATH": "/tmp",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.GeoipPath != "/tmp" {
		t.Errorf("Expected --geoip-path=/tmp, got value=%v", cfg.GeoipPath)
	}
}

func TestConfigMaxCountries(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--max-countries", "10"})

	if cfg.MaxCountries != 10 {
		t.Errorf("Expected --max-countries=10, got value=%v", cfg.MaxCountries)
	}
}

func TestConfigEnvMaxCountries(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAX_COUNTRIES": "10",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.MaxCountries != 10 {
		t.Errorf("Expected --max-countries=10, got value=%v", cfg.MaxCountries)
	}
}

func TestConfigMaxIPs(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--max-ips", "100"})

	if cfg.MaxIPs != 100 {
		t.Errorf("Expected --max-ips=100, got value=%v", cfg.MaxIPs)
	}
}

func TestConfigEnvMaxIPs(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAX_IPS": "100",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.MaxIPs != 100 {
		t.Errorf("Expected --max-ips=100, got value=%v", cfg.MaxIPs)
	}
}

func TestConfigBlockedNoExpire(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--block-permanent"})

	if cfg.BlockedNoExpire != true {
		t.Errorf("Expected --block-permanent, got value=%v", cfg.BlockedNoExpire)
	}
}

func TestConfigEnvBlockedNoExpire(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_BLOCK_PERMANENT": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.BlockedNoExpire != true {
		t.Errorf("Expected --block-permanent, got value=%v", cfg.BlockedNoExpire)
	}
}

func TestConfigCustomSettings(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--custom-settings-path", "/tmp"})

	if cfg.CustomSettingsPath != "/tmp" {
		t.Errorf("Expected --custom-settings-path=/tmp, got value=%v", cfg.CustomSettingsPath)
	}
}

func TestConfigEnvCustomSettings(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_CUSTOM_SETTINGS_PATH": "/tmp",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.CustomSettingsPath != "/tmp" {
		t.Errorf("Expected --custom-settings-path=/tmp, got value=%v", cfg.CustomSettingsPath)
	}
}

func TestConfigHTTPUseBasicAuth(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--http-use-basic-auth"})

	if cfg.HTTPApp.useBasicAuth != true {
		t.Errorf("Expected --http-use-basic-auth, got value=%v", cfg.HTTPApp.useBasicAuth)
	}
}

func TestConfigEnvHTTPUseBasicAuth(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_USE_BASIC_AUTH": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.HTTPApp.useBasicAuth != true {
		t.Errorf("Expected --http-use-basic-auth, got value=%v", cfg.HTTPApp.useBasicAuth)
	}
}

func TestConfigHTTPBasicAuthUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--http-use-basic-auth", "--http-basic-auth-username", "username"})

	if cfg.HTTPApp.auth.username != "username" {
		t.Errorf("Expected --http-basic-auth-username=username, got value=%v", cfg.HTTPApp.auth.username)
	}
}

func TestConfigEnvHTTPBasicAuthUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_USE_BASIC_AUTH":      "true",
		"GEOIPPOLICYD_HTTP_BASIC_AUTH_USERNAME": "username",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.HTTPApp.auth.username != "username" {
		t.Errorf("Expected --http-basic-auth-username=username, got value=%v", cfg.HTTPApp.auth.username)
	}
}

func TestConfigHTTPBasicAuthPassword(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--http-use-basic-auth", "--http-basic-auth-password", "password"})

	if cfg.HTTPApp.auth.password != "password" {
		t.Errorf("Expected --http-basic-auth-password=password, got value=%v", cfg.HTTPApp.auth.password)
	}
}

func TestConfigEnvHTTPBasicAuthPassword(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_USE_BASIC_AUTH":      "true",
		"GEOIPPOLICYD_HTTP_BASIC_AUTH_PASSWORD": "password",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.HTTPApp.auth.password != "password" {
		t.Errorf("Expected --http-basic-auth-password=password, got value=%v", cfg.HTTPApp.auth.password)
	}
}

func TestConfigHTTPUseSSL(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--http-use-ssl"})

	if cfg.HTTPApp.useSSL != true {
		t.Errorf("Expected --http-use-ssl, got value=%v", cfg.HTTPApp.useSSL)
	}
}

func TestConfigEnvHTTPUseSSL(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_USE_SSL": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.HTTPApp.useSSL != true {
		t.Errorf("Expected --http-use-ssl, got value=%v", cfg.HTTPApp.useSSL)
	}
}

func TestConfigHTTPTLSCert(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--http-use-ssl", "--http-tls-cert", "/tmp"})

	if cfg.HTTPApp.x509.cert != "/tmp" {
		t.Errorf("Expected --http-tls-cert=/tmp, got value=%v", cfg.HTTPApp.x509.cert)
	}
}

func TestConfigEnvHTTPTLSCert(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_USE_SSL":  "true",
		"GEOIPPOLICYD_HTTP_TLS_CERT": "/tmp",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.HTTPApp.x509.cert != "/tmp" {
		t.Errorf("Expected --http-tls-cert=/tmp, got value=%v", cfg.HTTPApp.x509.cert)
	}
}

func TestConfigHTTPTLSKey(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--http-use-ssl", "--http-tls-key", "/tmp"})

	if cfg.HTTPApp.x509.key != "/tmp" {
		t.Errorf("Expected --http-tls-key=/tmp, got value=%v", cfg.HTTPApp.x509.key)
	}
}

func TestConfigEnvHTTPTLSKey(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_USE_SSL": "true",
		"GEOIPPOLICYD_HTTP_TLS_KEY": "/tmp",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.HTTPApp.x509.key != "/tmp" {
		t.Errorf("Expected --http-tls-key=/tmp, got value=%v", cfg.HTTPApp.x509.key)
	}
}

func TestConfigUseLDAP(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap"})

	if cfg.UseLDAP != true {
		t.Errorf("Expected --use-ldap, got value=%v", cfg.UseLDAP)
	}
}

func TestConfigEnvUseLDAP(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.UseLDAP != true {
		t.Errorf("Expected --use-ldap, got value=%v", cfg.UseLDAP)
	}
}

func TestConfigLDAPServerUris(t *testing.T) {
	cfg := &CmdLineConfig{}
	u1 := "ldap://localhost:389/"
	u2 := "ldap://example.com:389/"
	f1 := false
	f2 := false
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-server-uri", u1, "--ldap-server-uri", u2})

	for _, v := range cfg.LDAP.ServerURIs {
		if v == u1 {
			f1 = true

			break
		}
	}

	for _, v := range cfg.LDAP.ServerURIs {
		if v == u2 {
			f2 = true

			break
		}
	}

	if f1 != true && f2 != true {
		t.Errorf("Expected --ldap-server-uri=%s --ldap-server-uri=%s, got value=%v", u1, u2, cfg.LDAP.ServerURIs)
	}
}

func TestConfigEnvLDAPServerUris(t *testing.T) {
	u1 := "ldap://localhost:389/"
	u2 := "ldap://example.com:389/"
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":         "true",
		"GEOIPPOLICYD_LDAP_SERVER_URIS": fmt.Sprintf("%s, %s", u1, u2),
	})
	defer closer()
	cfg := &CmdLineConfig{}
	f1 := false
	f2 := false
	cfg.Init([]string{"app", "server"})

	for _, v := range cfg.LDAP.ServerURIs {
		if v == u1 {
			f1 = true

			break
		}
	}

	for _, v := range cfg.LDAP.ServerURIs {
		if v == u2 {
			f2 = true

			break
		}
	}

	if f1 != true && f2 != true {
		t.Errorf("Expected --ldap-server-uri=%s --ldap-server-uri=%s, got value=%v", u1, u2, cfg.LDAP.ServerURIs)
	}
}

func TestConfigLDAPBaseDN(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-basedn", "o=org"})

	if cfg.LDAP.BaseDN != "o=org" {
		t.Errorf("Expected --ldap-basedn=o=org, got value=%v", cfg.LDAP.BaseDN)
	}
}

func TestConfigEnvLDAPBaseDN(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":    "true",
		"GEOIPPOLICYD_LDAP_BASEDN": "o=org",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.BaseDN != "o=org" {
		t.Errorf("Expected --ldap-basedn=o=org, got value=%v", cfg.LDAP.BaseDN)
	}
}

func TestConfigLDAPBindDN(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-binddn", "cn=admin,o=org"})

	if cfg.LDAP.BindDN != "cn=admin,o=org" {
		t.Errorf("Expected --ldap-binddn=cn=admin,o=org, got value=%v", cfg.LDAP.BindDN)
	}
}

func TestConfigEnvLDAPBindDN(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":    "true",
		"GEOIPPOLICYD_LDAP_BINDDN": "cn=admin,o=org",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.BindDN != "cn=admin,o=org" {
		t.Errorf("Expected --ldap-binddn=cn=admin,o=org, got value=%v", cfg.LDAP.BindDN)
	}
}

func TestConfigLDAPBindPW(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-bindpw", "password"})

	if cfg.LDAP.BindPW != "password" {
		t.Errorf("Expected --ldap-bindpw=password, got value=%v", cfg.LDAP.BindPW)
	}
}

func TestConfigEnvLDAPBindPW(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":    "true",
		"GEOIPPOLICYD_LDAP_BINDPW": "password",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.BindPW != "password" {
		t.Errorf("Expected --ldap-bindpw=password, got value=%v", cfg.LDAP.BindPW)
	}
}

func TestConfigLDAPFilter(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-filter", "(objectClass=*)"})

	if cfg.LDAP.Filter != "(objectClass=*)" {
		t.Errorf("Expected --ldap-filter=(objectClass=*), got value=%v", cfg.LDAP.Filter)
	}
}

func TestConfigEnvLDAPFilter(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":    "true",
		"GEOIPPOLICYD_LDAP_FILTER": "(objectClass=*)",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.Filter != "(objectClass=*)" {
		t.Errorf("Expected --ldap-filter=(objectClass=*), got value=%v", cfg.LDAP.Filter)
	}
}

func TestConfigLDAPResultAttribute(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-result-attribute", "mail"})

	if cfg.LDAP.ResultAttr[0] != "mail" {
		t.Errorf("Expected --ldap-result-attribute=mail, got value=%v", cfg.LDAP.ResultAttr)
	}
}

func TestConfigEnvLDAPResultAttribute(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":              "true",
		"GEOIPPOLICYD_LDAP_RESULT_ATTRIBUTE": "mail",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.ResultAttr[0] != "mail" {
		t.Errorf("Expected --ldap-result-attribute=mail, got value=%v", cfg.LDAP.ResultAttr)
	}
}

func TestConfigLDAPStartTLS(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-starttls"})

	if cfg.LDAP.StartTLS != true {
		t.Errorf("Expected --ldap-starttls, got value=%v", cfg.LDAP.StartTLS)
	}
}

func TestConfigLDAPPoolSize(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-pool-size", "100"})

	if cfg.LDAP.PoolSize != 100 {
		t.Errorf("Expected --ldap-pool-size, got value=%v", cfg.LDAP.PoolSize)
	}
}

func TestConfigEnvLDAPPoolSize(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":       "true",
		"GEOIPPOLICYD_LDAP_POOL_SIZE": "100",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.PoolSize != 100 {
		t.Errorf("Expected --ldap-pool-size=100, got value=%v", cfg.LDAP.PoolSize)
	}
}

func TestConfigEnvLDAPStartTLS(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":      "true",
		"GEOIPPOLICYD_LDAP_STARTTLS": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.StartTLS != true {
		t.Errorf("Expected --ldap-starttls, got value=%v", cfg.LDAP.StartTLS)
	}
}

func TestConfigLDAPTLSSkipVerify(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-tls-skip-verify"})

	if cfg.LDAP.TLSSkipVerify != true {
		t.Errorf("Expected --ldap-tls-skip-verify, got value=%v", cfg.LDAP.TLSSkipVerify)
	}
}

func TestConfigEnvLDAPTLSSkipVerify(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":             "true",
		"GEOIPPOLICYD_LDAP_TLS_SKIP_VERIFY": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.TLSSkipVerify != true {
		t.Errorf("Expected --ldap-tls-skip-verify, got value=%v", cfg.LDAP.TLSSkipVerify)
	}
}

func TestConfigLDAPTLSClientCert(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-tls-client-cert", "/tmp"})

	if cfg.LDAP.TLSClientCert != "/tmp" {
		t.Errorf("Expected --ldap-tls-client-cert=/tmp, got value=%v", cfg.LDAP.TLSClientCert)
	}
}

func TestConfigEnvLDAPTLSClientCert(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":             "true",
		"GEOIPPOLICYD_LDAP_TLS_CLIENT_CERT": "/tmp",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.TLSClientCert != "/tmp" {
		t.Errorf("Expected --ldap-tls-client-cert=/tmp, got value=%v", cfg.LDAP.TLSClientCert)
	}
}

func TestConfigLDAPTLSClientKey(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-tls-client-key", "/tmp"})

	if cfg.LDAP.TLSClientKey != "/tmp" {
		t.Errorf("Expected --ldap-tls-client-key=/tmp, got value=%v", cfg.LDAP.TLSClientKey)
	}
}

func TestConfigEnvLDAPTLSClientKey(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":            "true",
		"GEOIPPOLICYD_LDAP_TLS_CLIENT_KEY": "/tmp",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.TLSClientKey != "/tmp" {
		t.Errorf("Expected --ldap-tls-client-key=/tmp, got value=%v", cfg.LDAP.TLSClientKey)
	}
}

func TestConfigLDAPSASLExternal(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-sasl-external"})

	if cfg.LDAP.SASLExternal != true {
		t.Errorf("Expected --ldap-sasl-external, got value=%v", cfg.LDAP.SASLExternal)
	}
}

func TestConfigEnvLDAPSASLExternal(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":           "true",
		"GEOIPPOLICYD_LDAP_SASL_EXTERNAL": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.SASLExternal != true {
		t.Errorf("Expected --ldap-sasl-external, got value=%v", cfg.LDAP.SASLExternal)
	}
}

func TestConfigLDAPScopeBase(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-scope", BASE})

	if cfg.LDAP.Scope != ldap.ScopeBaseObject {
		t.Errorf("Expected --ldap-scope=base (%d), got value=%v", ldap.ScopeBaseObject, cfg.LDAP.Scope)
	}
}

func TestConfigEnvLDAPScopeBase(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":   "true",
		"GEOIPPOLICYD_LDAP_SCOPE": "base",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.Scope != ldap.ScopeBaseObject {
		t.Errorf("Expected --ldap-scope=base (%d), got value=%v", ldap.ScopeBaseObject, cfg.LDAP.Scope)
	}
}

func TestConfigLDAPScopeOne(t *testing.T) {
	cfg := CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-scope", ONE})

	if cfg.LDAP.Scope != ldap.ScopeSingleLevel {
		t.Errorf("Expected --ldap-scope=one (%d), got value=%v", ldap.ScopeSingleLevel, cfg.LDAP.Scope)
	}
}

func TestConfigEnvLDAPScopeOne(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":   "true",
		"GEOIPPOLICYD_LDAP_SCOPE": "one",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.Scope != ldap.ScopeSingleLevel {
		t.Errorf("Expected --ldap-scope=one (%d), got value=%v", ldap.ScopeSingleLevel, cfg.LDAP.Scope)
	}
}

func TestConfigLDAPScopeSub(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--use-ldap", "--ldap-scope", SUB})

	if cfg.LDAP.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("Expected --ldap-scope=sub (%d), got value=%v", ldap.ScopeWholeSubtree, cfg.LDAP.Scope)
	}
}

func TestConfigEnvLDAPScopeSub(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_LDAP":   "true",
		"GEOIPPOLICYD_LDAP_SCOPE": "sub",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.LDAP.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("Expected --ldap-scope=sub (%d), got value=%v", ldap.ScopeWholeSubtree, cfg.LDAP.Scope)
	}
}

func TestConfigRunActions(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--run-actions"})

	if cfg.RunActions != true {
		t.Errorf("Expected --run-actions, got value=%v", cfg.RunActions)
	}
}

func TestConfigEnvRunActions(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_RUN_ACTIONS": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RunActions != true {
		t.Errorf("Expected --run-actions, got value=%v", cfg.RunActions)
	}
}

func TestConfigRunActionOperator(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--run-actions", "--run-action-operator"})

	if cfg.RunActionOperator != true {
		t.Errorf("Expected --run-action-operator, got value=%v", cfg.RunActionOperator)
	}
}

func TestConfigEnvRunActionOperator(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_RUN_ACTIONS":         "true",
		"GEOIPPOLICYD_RUN_ACTION_OPERATOR": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.RunActionOperator != true {
		t.Errorf("Expected --run-action-operator, got value=%v", cfg.RunActionOperator)
	}
}

func TestConfigOperatorTo(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--run-actions", "--run-action-operator", "--operator-to", "test"})

	if cfg.EmailOperatorTo != "test" {
		t.Errorf("Expected --operator-to=test, got value=%v", cfg.EmailOperatorTo)
	}
}

func TestConfigEnvOperatorTo(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_RUN_ACTIONS":         "true",
		"GEOIPPOLICYD_RUN_ACTION_OPERATOR": "true",
		"GEOIPPOLICYD_OPERATOR_TO":         "test",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.EmailOperatorTo != "test" {
		t.Errorf("Expected --operator-to=test, got value=%v", cfg.EmailOperatorTo)
	}
}

func TestConfigOperatorFrom(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--run-actions", "--run-action-operator", "--operator-from", "test"})

	if cfg.EmailOperatorFrom != "test" {
		t.Errorf("Expected --operator-from=test, got value=%v", cfg.EmailOperatorFrom)
	}
}

func TestConfigEnvOperatorFrom(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_RUN_ACTIONS":         "true",
		"GEOIPPOLICYD_RUN_ACTION_OPERATOR": "true",
		"GEOIPPOLICYD_OPERATOR_FROM":       "test",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.EmailOperatorFrom != "test" {
		t.Errorf("Expected --operator-from=test, got value=%v", cfg.EmailOperatorFrom)
	}
}

func TestConfigOperatorSubject(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--run-actions", "--run-action-operator", "--operator-subject", "test"})

	if cfg.EmailOperatorSubject != "test" {
		t.Errorf("Expected --operator-subject=test, got value=%v", cfg.EmailOperatorSubject)
	}
}

func TestConfigEnvOperatorSubject(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_RUN_ACTIONS":         "true",
		"GEOIPPOLICYD_RUN_ACTION_OPERATOR": "true",
		"GEOIPPOLICYD_OPERATOR_SUBJECT":    "test",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.EmailOperatorSubject != "test" {
		t.Errorf("Expected --operator-subject=test, got value=%v", cfg.EmailOperatorSubject)
	}
}

func TestConfigOperatorMessageCT(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--run-actions", "--run-action-operator", "--operator-message-ct", "text/html"})

	if cfg.EmailOperatorMessageCT != "text/html" {
		t.Errorf("Expected --operator-message-ct=text/html, got value=%v", cfg.EmailOperatorMessageCT)
	}
}

func TestConfigEnvOperatorMessageCT(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_RUN_ACTIONS":         "true",
		"GEOIPPOLICYD_RUN_ACTION_OPERATOR": "true",
		"GEOIPPOLICYD_OPERATOR_MESSAGE_CT": "text/html",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.EmailOperatorMessageCT != "text/html" {
		t.Errorf("Expected --operator-message-ct=text/html, got value=%v", cfg.EmailOperatorMessageCT)
	}
}

func TestConfigOperatorMessagePath(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--run-actions", "--run-action-operator", "--operator-message-path", "/tmp"})

	if cfg.EmailOperatorMessagePath != "/tmp" {
		t.Errorf("Expected --operator-message-path=/tmp, got value=%v", cfg.EmailOperatorMessagePath)
	}
}

func TestConfigEnvOperatorMessagePath(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_RUN_ACTIONS":           "true",
		"GEOIPPOLICYD_RUN_ACTION_OPERATOR":   "true",
		"GEOIPPOLICYD_OPERATOR_MESSAGE_PATH": "/tmp",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.EmailOperatorMessagePath != "/tmp" {
		t.Errorf("Expected --operator-message-path=/tmp, got value=%v", cfg.EmailOperatorMessagePath)
	}
}

func TestConfigMailServerAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--mail-server-address", "mail.google.com"})

	if cfg.MailServer != "mail.google.com" {
		t.Errorf("Expected --mail-server-address=mail.google.com, got value=%v", cfg.MailServer)
	}
}

func TestConfigEnvMailServerAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_SERVER_ADDRESS": "mail.google.com",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.MailServer != "mail.google.com" {
		t.Errorf("Expected --mail-server-address=mail.google.com, got value=%v", cfg.MailServer)
	}
}

func TestConfigMailHelo(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--mail-helo", "localhost.localdomain"})

	if cfg.MailHelo != "localhost.localdomain" {
		t.Errorf("Expected --mail-helo=localhost.localdomain, got value=%v", cfg.MailHelo)
	}
}

func TestConfigEnvMailHelo(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_HELO": "localhost.localdomain",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.MailHelo != "localhost.localdomain" {
		t.Errorf("Expected --mail-helo=localhost.localdomain, got value=%v", cfg.MailHelo)
	}
}

func TestConfigMailPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--mail-server-port", "465"})

	if cfg.MailPort != 465 {
		t.Errorf("Expected --mail-port=465, got value=%v", cfg.MailPort)
	}
}

func TestConfigEnvMailPort(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_SERVER_PORT": "465",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.MailPort != 465 {
		t.Errorf("Expected --mail-server-port=465, got value=%v", cfg.MailPort)
	}
}

func TestConfigMailUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--mail-username", "username"})

	if cfg.MailUsername != "username" {
		t.Errorf("Expected --mail-username=username, got value=%v", cfg.MailUsername)
	}
}

func TestConfigEnvMailUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_USERNAME": "username",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.MailUsername != "username" {
		t.Errorf("Expected --mail-username=username, got value=%v", cfg.MailUsername)
	}
}

func TestConfigMailPassword(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--mail-password", "password"})

	if cfg.MailPassword != "password" {
		t.Errorf("Expected --mail-password=password, got value=%v", cfg.MailPassword)
	}
}

func TestConfigEnvMailPassword(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_PASSWORD": "password",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.MailPassword != "password" {
		t.Errorf("Expected --mail-password=password, got value=%v", cfg.MailPassword)
	}
}

func TestConfigMailSSL(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server", "--mail-ssl-on-connect"})

	if cfg.MailSSL != true {
		t.Errorf("Expected --mail-ssl-on-connect, got value=%v", cfg.MailSSL)
	}
}

func TestConfigEnvMailSSL(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_SSL_ON_CONNECT": "true",
	})
	defer closer()
	cfg := &CmdLineConfig{}
	cfg.Init([]string{"app", "server"})

	if cfg.MailSSL != true {
		t.Errorf("Expected --mail-ssl, got value=%v", cfg.MailSSL)
	}
}
