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
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

const (
	testCommandApp            = "app"
	testCommandServer         = "server"
	testEnvHTTPUseBasicAuth   = "GEOIPPOLICYD_HTTP_USE_BASIC_AUTH"
	testEnvHTTPUseSSL         = "GEOIPPOLICYD_HTTP_USE_SSL"
	testEnvLDAPScope          = "GEOIPPOLICYD_LDAP_SCOPE"
	testEnvMaxCountries       = "GEOIPPOLICYD_MAX_COUNTRIES"
	testEnvMaxHomeCountries   = "GEOIPPOLICYD_MAX_HOME_COUNTRIES"
	testEnvMaxHomeIPs         = "GEOIPPOLICYD_MAX_HOME_IPS"
	testEnvMaxIPs             = "GEOIPPOLICYD_MAX_IPS"
	testEnvRunActionOperator  = "GEOIPPOLICYD_RUN_ACTION_OPERATOR"
	testEnvRunActions         = "GEOIPPOLICYD_RUN_ACTIONS"
	testEnvUseLDAP            = "GEOIPPOLICYD_USE_LDAP"
	testEnvVerboseLevel       = "GEOIPPOLICYD_VERBOSE_LEVEL"
	testFlagGeoIPPath         = "--geoip-path"
	testFlagHomeCountries     = "--home-countries"
	testFlagHTTPUseBasicAuth  = "--http-use-basic-auth"
	testFlagHTTPUseSSL        = "--http-use-ssl"
	testFlagLDAPScope         = "--ldap-scope"
	testFlagLDAPServerURI     = "--ldap-server-uri"
	testFlagMaxCountries      = "--max-countries"
	testFlagMaxHomeCountries  = "--max-home-countries"
	testFlagMaxHomeIPs        = "--max-home-ips"
	testFlagMaxIPs            = "--max-ips"
	testFlagRedisSentinels    = "--redis-sentinels"
	testFlagRunActionOperator = "--run-action-operator"
	testFlagRunActions        = "--run-actions"
	testFlagUseLDAP           = "--use-ldap"
	testFlagVerbose           = "--verbose"
	testHTTPAddress           = "192.168.0.1"
	testLDAPBaseDN            = "o=org"
	testLDAPBindDN            = "cn=admin,o=org"
	testLDAPFilter            = "(objectClass=*)"
	testLDAPResultAttribute   = "mail"
	testLDAPURIExample        = "ldap://example.com:389/"
	testLDAPURILocalhost      = "ldap://localhost:389/"
	testMailHeloHost          = "localhost.localdomain"
	testMailHost              = "mail.google.com"
	testPathTmp               = "/tmp"
	testRedisPrefixAlt        = "some_prefix_"
	testRedisSentinel1        = "10.0.0.1:26379"
	testRedisSentinel2        = "10.0.0.2:26379"
	testRedisSentinelMaster   = "mymaster"
	testServerAddress         = "172.16.23.45"
	testTextHTML              = "text/html"
	testValueGeneric          = "test"
	testValueHundred          = "100"
	testValuePassword         = "password"
	testValueTen              = "10"
	testValueTrue             = "true"
	testValueUsername         = "username"
	testVerboseNameDebug      = verboseNameDebug
	testVerboseNameInfo       = verboseNameInfo
	testVerboseNameNone       = verboseNameNone
	testBooleanFalse          = "false"
	testOTLPEndpoint          = "http://collector.example:4318"
	testOTLPHeaders           = "tenant=mail,token=secret"
	testOTLPSampleRatio       = "0.25"
	testOTLPSecret            = "secret"
	testOTelEnabledFlag       = "--otel-enabled"
	testOTelService           = "geoip-policyd-test"
	testOTelVersion           = "test-version"
	testPrometheusMetrics     = "/internal/metrics"
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
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.VerboseLevel != logLevelNone {
		t.Errorf("Expected --verbose not set, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigEnvVerboseNone(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvVerboseLevel: testVerboseNameNone,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.VerboseLevel != logLevelNone {
		t.Errorf("Expected --verbose not set, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigVerboseInfo(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagVerbose})

	if cfg.VerboseLevel != logLevelInfo {
		t.Errorf("Expected --verbose, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigEnvVerboseInfo(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvVerboseLevel: testVerboseNameInfo,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.VerboseLevel != logLevelInfo {
		t.Errorf("Expected --verbose, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigVerboseDebug(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagVerbose, testFlagVerbose})

	if cfg.VerboseLevel != logLevelDebug {
		t.Errorf("Expected --verbose --verbose, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigEnvVerboseDebug(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvVerboseLevel: testVerboseNameDebug,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.VerboseLevel != logLevelDebug {
		t.Errorf("Expected --verbose --verbose, got value=%v", cfg.VerboseLevel)
	}
}

func TestConfigServerAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--server-address", testServerAddress})

	if cfg.ServerAddress != testServerAddress {
		t.Errorf("Expected --server-address=172.16.23.45, got value=%v", cfg.ServerAddress)
	}
}

func TestConfigEnvServerAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_SERVER_ADDRESS": testServerAddress,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.ServerAddress != testServerAddress {
		t.Errorf("Expected --server-address=172.16.23.45, got value=%v", cfg.ServerAddress)
	}
}

func TestConfigServerPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--server-port", "9000"})

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
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.ServerPort != 9000 {
		t.Errorf("Expected --server-port=9000, got value=%v", cfg.ServerPort)
	}
}

func TestConfigUseSASLUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--sasl-username"})

	if cfg.UseSASLUsername != true {
		t.Errorf("Expected --sasl-username, got value=%v", cfg.UseSASLUsername)
	}
}

func TestConfigEnvUseSASLUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_USE_SASL_USERNAME": testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.UseSASLUsername != true {
		t.Errorf("Expected --sasl-username, got value=%v", cfg.ServerPort)
	}
}

func TestConfigHTTPAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--http-address", testHTTPAddress})

	if cfg.HTTPAddress != testHTTPAddress {
		t.Errorf("Expected --http-address=192.168.0.1, got value=%v", cfg.HTTPAddress)
	}
}

func TestConfigHTTPPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--http-port", "80"})

	if cfg.HTTPPort != 80 {
		t.Errorf("Expected --http-port=80, got value=%v", cfg.HTTPPort)
	}
}

func TestConfigEnvHTTPAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_ADDRESS": testHTTPAddress,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.HTTPAddress != testHTTPAddress {
		t.Errorf("Expected --http-address=192.168.0.1, got value=%v", cfg.HTTPAddress)
	}
}

func TestConfigEnvHTTPPort(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HTTP_PORT": "80",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.HTTPPort != 80 {
		t.Errorf("Expected --http-port=80, got value=%v", cfg.HTTPPort)
	}
}

func TestConfigRedisAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-address", testHTTPAddress})

	if cfg.RedisAddress != testHTTPAddress {
		t.Errorf("Expected --redis-address=192.168.0.1, got value=%v", cfg.RedisAddress)
	}
}

func TestConfigEnvRedisAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_ADDRESS": testHTTPAddress,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisAddress != testHTTPAddress {
		t.Errorf("Expected --redis-address=192.168.0.1, got value=%v", cfg.RedisAddress)
	}
}

func TestConfigRedisPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-port", "6333"})

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
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisPort != 6333 {
		t.Errorf("Expected --redis-port=6333, got value=%v", cfg.RedisPort)
	}
}

func TestConfigRedisDatabaseNumber(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-database-number", "4"})

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
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisDB != 4 {
		t.Errorf("Expected --redis-database-number=4, got value=%v", cfg.RedisDB)
	}
}

func TestConfigRedisUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-username", testValueUsername})

	if cfg.RedisUsername != testValueUsername {
		t.Errorf("Expected --redis-username=username, got value=%v", cfg.RedisUsername)
	}
}

func TestConfigEnvRedisUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_USERNAME": testValueUsername,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisUsername != testValueUsername {
		t.Errorf("Expected --redis-username=username, got value=%v", cfg.RedisUsername)
	}
}

func TestConfigRedisSentinelUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-sentinel-username", testValueUsername})

	if cfg.RedisSentinelUsername != testValueUsername {
		t.Errorf("Expected --redis-sentinel-username=username, got value=%v", cfg.RedisSentinelUsername)
	}
}

func TestConfigEnvRedisSentinelUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_SENTINEL_USERNAME": testValueUsername,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisSentinelUsername != testValueUsername {
		t.Errorf("Expected --redis-sentinel-username=username, got value=%v", cfg.RedisSentinelUsername)
	}
}

func TestConfigRedisPassword(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-password", testValuePassword})

	if cfg.RedisPassword != testValuePassword {
		t.Errorf("Expected --redis-password=password, got value=%v", cfg.RedisPassword)
	}
}

func TestConfigEnvRedisPassword(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_PASSWORD": testValuePassword,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisPassword != testValuePassword {
		t.Errorf("Expected --redis-password=password, got value=%v", cfg.RedisPassword)
	}
}

func TestConfigRedisSentinelPassword(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-sentinel-password", testValuePassword})

	if cfg.RedisSentinelPassword != testValuePassword {
		t.Errorf("Expected --redis-sentinel-password=password, got value=%v", cfg.RedisSentinelPassword)
	}
}

func TestConfigEnvRedisSentinelPassword(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_SENTINEL_PASSWORD": testValuePassword,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisSentinelPassword != testValuePassword {
		t.Errorf("Expected --redis-sentinel-password=password, got value=%v", cfg.RedisSentinelPassword)
	}
}

func TestConfigRedisReplicaAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-replica-address", testHTTPAddress})

	if cfg.RedisAddressRO != testHTTPAddress {
		t.Errorf("Expected --redis-replica-address=192.168.0.1, got value=%v", cfg.RedisAddressRO)
	}
}

func TestConfigEnvRedisReplicaAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_REPLICA_ADDRESS": testHTTPAddress,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisAddressRO != testHTTPAddress {
		t.Errorf("Expected --redis-replica-address=192.168.0.1, got value=%v", cfg.RedisAddressRO)
	}
}

func TestConfigRedisReplicaPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-replica-port", "6333"})

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
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisPortRO != 6333 {
		t.Errorf("Expected --redis-replica-port=6333, got value=%v", cfg.RedisPortRO)
	}
}

func TestConfigRedisSentinels(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagRedisSentinels, testRedisSentinel1, testFlagRedisSentinels, testRedisSentinel2})

	if cfg.RedisSentinels[0] != testRedisSentinel1 && cfg.RedisSentinels[1] != testRedisSentinel2 {
		t.Errorf("Expected --redis-sentinels='10.0.0.1:26379 10.0.0.2:26379', got value=%v", cfg.RedisSentinels)
	}
}

func TestConfigEnvRedisSentinels(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_SENTINELS": "10.0.0.1:26379 10.0.0.2:26379",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisSentinels[0] != testRedisSentinel1 && cfg.RedisSentinels[1] != testRedisSentinel2 {
		t.Errorf("Expected --redis-sentinels='10.0.0.1:26379 10.0.0.2:26379', got value=%v", cfg.RedisSentinels)
	}
}

func TestConfigRedisSentinelMasterName(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-sentinel-master-name", testRedisSentinelMaster})

	if cfg.RedisSentinelMasterName != testRedisSentinelMaster {
		t.Errorf("Expected --redis-sentinel-master-name=mymaster, got value=%v", cfg.RedisSentinelMasterName)
	}
}

func TestConfigEnvRedisSentinelMasterName(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_SENTINEL_MASTER_NAME": testRedisSentinelMaster,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisSentinelMasterName != testRedisSentinelMaster {
		t.Errorf("Expected --redis-sentinel-master-name=mymaster, got value=%v", cfg.RedisSentinelMasterName)
	}
}

func TestConfigRedisPrefix(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-prefix", testRedisPrefixAlt})

	if cfg.RedisPrefix != testRedisPrefixAlt {
		t.Errorf("Expected --redis-prefix=some_prefix_, got value=%v", cfg.RedisPrefix)
	}
}

func TestConfigEnvRedisPrefix(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_REDIS_PREFIX": testRedisPrefixAlt,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisPrefix != testRedisPrefixAlt {
		t.Errorf("Expected --redis-prefix=some_prefix_, got value=%v", cfg.RedisPrefix)
	}
}

func TestConfigRedisTTL(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--redis-ttl", "300"})

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
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RedisTTL != 300 {
		t.Errorf("Expected --redis-ttl=300, got value=%v", cfg.RedisTTL)
	}
}

func TestConfigGeoIPPath(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagGeoIPPath, testPathTmp})

	if cfg.GeoipPath != testPathTmp {
		t.Errorf("Expected --geoip-path=/tmp, got value=%v", cfg.GeoipPath)
	}
}

func TestConfigEnvGeoIPPath(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_GEOIP_PATH": testPathTmp,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.GeoipPath != testPathTmp {
		t.Errorf("Expected --geoip-path=/tmp, got value=%v", cfg.GeoipPath)
	}
}

func TestConfigMaxCountries(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagMaxCountries, testValueTen})

	if cfg.MaxCountries != 10 {
		t.Errorf("Expected --max-countries=10, got value=%v", cfg.MaxCountries)
	}
}

func TestConfigMaxCountriesZero(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagMaxCountries, "0"})

	if cfg.MaxCountries != 0 {
		t.Errorf("Expected --max-countries=0, got value=%v", cfg.MaxCountries)
	}
}

func TestConfigEnvMaxCountries(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvMaxCountries: testValueTen,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MaxCountries != 10 {
		t.Errorf("Expected --max-countries=10, got value=%v", cfg.MaxCountries)
	}
}

func TestConfigEnvMaxCountriesZero(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvMaxCountries: "0",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MaxCountries != 0 {
		t.Errorf("Expected --max-countries=0, got value=%v", cfg.MaxCountries)
	}
}

func TestConfigMaxIPs(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagMaxIPs, testValueHundred})

	if cfg.MaxIPs != 100 {
		t.Errorf("Expected --max-ips=100, got value=%v", cfg.MaxIPs)
	}
}

func TestConfigMaxIPsZero(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagMaxIPs, "0"})

	if cfg.MaxIPs != 0 {
		t.Errorf("Expected --max-ips=0, got value=%v", cfg.MaxIPs)
	}
}

func TestConfigEnvMaxIPs(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvMaxIPs: testValueHundred,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MaxIPs != 100 {
		t.Errorf("Expected --max-ips=100, got value=%v", cfg.MaxIPs)
	}
}

func TestConfigEnvMaxIPsZero(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvMaxIPs: "0",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MaxIPs != 0 {
		t.Errorf("Expected --max-ips=0, got value=%v", cfg.MaxIPs)
	}
}

func TestConfigHomeCountries(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagHomeCountries, testCountryDE, testFlagHomeCountries, testCountryAT})

	if cfg.HomeCountries[0] != testCountryDE && cfg.HomeCountries[1] != testCountryAT {
		t.Errorf("Expected --home-countries='DE AT', got value=%v", cfg.HomeCountries)
	}
}

func TestConfigEnvHomeCountries(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_HOME_COUNTRIES": "DE AT",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.HomeCountries[0] != testCountryDE && cfg.HomeCountries[1] != testCountryAT {
		t.Errorf("Expected --home-countries='DE AT', got value=%v", cfg.HomeCountries)
	}
}

func TestConfigMaxHomeCountries(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagMaxHomeCountries, testValueTen})

	if cfg.MaxHomeCountries != 10 {
		t.Errorf("Expected --max-home-countries=10, got value=%v", cfg.MaxHomeCountries)
	}
}

func TestConfigMaxHomeCountriesZero(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagMaxHomeCountries, "0"})

	if cfg.MaxHomeCountries != 0 {
		t.Errorf("Expected --max-home-countries=0, got value=%v", cfg.MaxHomeCountries)
	}
}

func TestConfigEnvMaxHomeCountries(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvMaxHomeCountries: testValueTen,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MaxHomeCountries != 10 {
		t.Errorf("Expected --max-home-countries=10, got value=%v", cfg.MaxHomeCountries)
	}
}

func TestConfigEnvMaxHomeCountriesZero(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvMaxHomeCountries: "0",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MaxHomeCountries != 0 {
		t.Errorf("Expected --max-home-countries=0, got value=%v", cfg.MaxHomeCountries)
	}
}

func TestConfigMaxHomeIPs(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagMaxHomeIPs, testValueHundred})

	if cfg.MaxHomeIPs != 100 {
		t.Errorf("Expected --max-home-ips=100, got value=%v", cfg.MaxHomeIPs)
	}
}

func TestConfigMaxHomeIPsZero(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagMaxHomeIPs, "0"})

	if cfg.MaxHomeIPs != 0 {
		t.Errorf("Expected --max-home-ips=0, got value=%v", cfg.MaxHomeIPs)
	}
}

func TestConfigEnvMaxHomeIPs(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvMaxHomeIPs: testValueHundred,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MaxHomeIPs != 100 {
		t.Errorf("Expected --max-home-ips=100, got value=%v", cfg.MaxHomeIPs)
	}
}

func TestConfigEnvMaxHomeIPsZero(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvMaxHomeIPs: "0",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MaxHomeIPs != 0 {
		t.Errorf("Expected --max-home-ips=0, got value=%v", cfg.MaxHomeIPs)
	}
}

func TestConfigBlockedNoExpire(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--block-permanent"})

	if cfg.BlockPermanent != true {
		t.Errorf("Expected --block-permanent, got value=%v", cfg.BlockPermanent)
	}
}

func TestConfigEnvBlockedNoExpire(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_BLOCK_PERMANENT": testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.BlockPermanent != true {
		t.Errorf("Expected --block-permanent, got value=%v", cfg.BlockPermanent)
	}
}

func TestConfigForceUserKnown(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--force-user-known"})

	if cfg.ForceUserKnown != true {
		t.Errorf("Expected --force-user-known, got value=%v", cfg.ForceUserKnown)
	}
}

func TestConfigEnvForceUserKnown(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_FORCE_USER_KNOWN": testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.ForceUserKnown != true {
		t.Errorf("Expected --force-user-known, got value=%v", cfg.ForceUserKnown)
	}
}

func TestConfigCustomSettings(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--custom-settings-path", testPathTmp})

	if cfg.CustomSettingsPath != testPathTmp {
		t.Errorf("Expected --custom-settings-path=/tmp, got value=%v", cfg.CustomSettingsPath)
	}
}

func TestConfigEnvCustomSettings(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_CUSTOM_SETTINGS_PATH": testPathTmp,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.CustomSettingsPath != testPathTmp {
		t.Errorf("Expected --custom-settings-path=/tmp, got value=%v", cfg.CustomSettingsPath)
	}
}

func TestConfigHTTPUseBasicAuth(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagHTTPUseBasicAuth})

	if cfg.useBasicAuth != true {
		t.Errorf("Expected --http-use-basic-auth, got value=%v", cfg.useBasicAuth)
	}
}

func TestConfigEnvHTTPUseBasicAuth(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvHTTPUseBasicAuth: testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.useBasicAuth != true {
		t.Errorf("Expected --http-use-basic-auth, got value=%v", cfg.useBasicAuth)
	}
}

func TestConfigHTTPBasicAuthUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagHTTPUseBasicAuth, "--http-basic-auth-username", testValueUsername})

	if cfg.auth.username != testValueUsername {
		t.Errorf("Expected --http-basic-auth-username=username, got value=%v", cfg.auth.username)
	}
}

func TestConfigEnvHTTPBasicAuthUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvHTTPUseBasicAuth:                 testValueTrue,
		"GEOIPPOLICYD_HTTP_BASIC_AUTH_USERNAME": testValueUsername,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.auth.username != testValueUsername {
		t.Errorf("Expected --http-basic-auth-username=username, got value=%v", cfg.auth.username)
	}
}

func TestConfigHTTPBasicAuthPassword(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagHTTPUseBasicAuth, "--http-basic-auth-password", testValuePassword})

	if cfg.auth.password != testValuePassword {
		t.Errorf("Expected --http-basic-auth-password=password, got value=%v", cfg.auth.password)
	}
}

func TestConfigEnvHTTPBasicAuthPassword(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvHTTPUseBasicAuth:                 testValueTrue,
		"GEOIPPOLICYD_HTTP_BASIC_AUTH_PASSWORD": testValuePassword,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.auth.password != testValuePassword {
		t.Errorf("Expected --http-basic-auth-password=password, got value=%v", cfg.auth.password)
	}
}

func TestConfigHTTPUseSSL(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagHTTPUseSSL})

	if cfg.useSSL != true {
		t.Errorf("Expected --http-use-ssl, got value=%v", cfg.useSSL)
	}
}

func TestConfigEnvHTTPUseSSL(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvHTTPUseSSL: testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.useSSL != true {
		t.Errorf("Expected --http-use-ssl, got value=%v", cfg.useSSL)
	}
}

func TestConfigHTTPTLSCert(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagHTTPUseSSL, "--http-tls-cert", testPathTmp})

	if cfg.x509.cert != testPathTmp {
		t.Errorf("Expected --http-tls-cert=/tmp, got value=%v", cfg.x509.cert)
	}
}

func TestConfigEnvHTTPTLSCert(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvHTTPUseSSL:            testValueTrue,
		"GEOIPPOLICYD_HTTP_TLS_CERT": testPathTmp,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.x509.cert != testPathTmp {
		t.Errorf("Expected --http-tls-cert=/tmp, got value=%v", cfg.x509.cert)
	}
}

func TestConfigHTTPTLSKey(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagHTTPUseSSL, "--http-tls-key", testPathTmp})

	if cfg.x509.key != testPathTmp {
		t.Errorf("Expected --http-tls-key=/tmp, got value=%v", cfg.x509.key)
	}
}

func TestConfigEnvHTTPTLSKey(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvHTTPUseSSL:           testValueTrue,
		"GEOIPPOLICYD_HTTP_TLS_KEY": testPathTmp,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.x509.key != testPathTmp {
		t.Errorf("Expected --http-tls-key=/tmp, got value=%v", cfg.x509.key)
	}
}

func TestConfigUseLDAP(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP})

	if cfg.UseLDAP != true {
		t.Errorf("Expected --use-ldap, got value=%v", cfg.UseLDAP)
	}
}

func TestConfigEnvUseLDAP(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP: testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.UseLDAP != true {
		t.Errorf("Expected --use-ldap, got value=%v", cfg.UseLDAP)
	}
}

func TestConfigLdapConfServerUris(t *testing.T) {
	cfg := &CmdLineConfig{}
	u1 := testLDAPURILocalhost
	u2 := testLDAPURIExample
	f1 := false
	f2 := false

	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, testFlagLDAPServerURI, u1, testFlagLDAPServerURI, u2})

	if slices.Contains(cfg.ServerURIs, u1) {
		f1 = true
	}

	if slices.Contains(cfg.ServerURIs, u2) {
		f2 = true
	}

	if f1 != true && f2 != true {
		t.Errorf("Expected --ldap-server-uri=%s --ldap-server-uri=%s, got value=%v", u1, u2, cfg.ServerURIs)
	}
}

func TestConfigEnvLdapConfServerUris(t *testing.T) {
	u1 := testLDAPURILocalhost
	u2 := testLDAPURIExample

	closer := envSetter(map[string]string{
		testEnvUseLDAP:                  testValueTrue,
		"GEOIPPOLICYD_LDAP_SERVER_URIS": fmt.Sprintf("%s, %s", u1, u2),
	})
	defer closer()

	cfg := &CmdLineConfig{}
	f1 := false
	f2 := false

	cfg.Init([]string{testCommandApp, testCommandServer})

	if slices.Contains(cfg.ServerURIs, u1) {
		f1 = true
	}

	if slices.Contains(cfg.ServerURIs, u2) {
		f2 = true
	}

	if f1 != true && f2 != true {
		t.Errorf("Expected --ldap-server-uri=%s --ldap-server-uri=%s, got value=%v", u1, u2, cfg.ServerURIs)
	}
}

func TestConfigLdapConfBaseDN(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-basedn", testLDAPBaseDN})

	if cfg.BaseDN != testLDAPBaseDN {
		t.Errorf("Expected --ldap-basedn=o=org, got value=%v", cfg.BaseDN)
	}
}

func TestConfigEnvLdapConfBaseDN(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:             testValueTrue,
		"GEOIPPOLICYD_LDAP_BASEDN": testLDAPBaseDN,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.BaseDN != testLDAPBaseDN {
		t.Errorf("Expected --ldap-basedn=o=org, got value=%v", cfg.BaseDN)
	}
}

func TestConfigLdapConfBindDN(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-binddn", testLDAPBindDN})

	if cfg.BindDN != testLDAPBindDN {
		t.Errorf("Expected --ldap-binddn=cn=admin,o=org, got value=%v", cfg.BindDN)
	}
}

func TestConfigEnvLdapConfBindDN(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:             testValueTrue,
		"GEOIPPOLICYD_LDAP_BINDDN": testLDAPBindDN,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.BindDN != testLDAPBindDN {
		t.Errorf("Expected --ldap-binddn=cn=admin,o=org, got value=%v", cfg.BindDN)
	}
}

func TestConfigLdapConfBindPW(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-bindpw", testValuePassword})

	if cfg.BindPW != testValuePassword {
		t.Errorf("Expected --ldap-bindpw=password, got value=%v", cfg.BindPW)
	}
}

func TestConfigEnvLdapConfBindPW(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:             testValueTrue,
		"GEOIPPOLICYD_LDAP_BINDPW": testValuePassword,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.BindPW != testValuePassword {
		t.Errorf("Expected --ldap-bindpw=password, got value=%v", cfg.BindPW)
	}
}

func TestConfigLdapConfFilter(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-filter", testLDAPFilter})

	if cfg.Filter != testLDAPFilter {
		t.Errorf("Expected --ldap-filter=(objectClass=*), got value=%v", cfg.Filter)
	}
}

func TestConfigEnvLdapConfFilter(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:             testValueTrue,
		"GEOIPPOLICYD_LDAP_FILTER": testLDAPFilter,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.Filter != testLDAPFilter {
		t.Errorf("Expected --ldap-filter=(objectClass=*), got value=%v", cfg.Filter)
	}
}

func TestConfigLdapConfResultAttribute(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-result-attribute", testLDAPResultAttribute})

	if cfg.SearchAttributes[0] != testLDAPResultAttribute {
		t.Errorf("Expected --ldap-result-attribute=mail, got value=%v", cfg.SearchAttributes)
	}
}

func TestConfigEnvLdapConfResultAttribute(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:                       testValueTrue,
		"GEOIPPOLICYD_LDAP_RESULT_ATTRIBUTE": testLDAPResultAttribute,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.SearchAttributes[0] != testLDAPResultAttribute {
		t.Errorf("Expected --ldap-result-attribute=mail, got value=%v", cfg.SearchAttributes)
	}
}

func TestConfigLdapConfStartTLS(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-starttls"})

	if cfg.StartTLS != true {
		t.Errorf("Expected --ldap-starttls, got value=%v", cfg.StartTLS)
	}
}

func TestConfigLdapConfIdlePoolSize(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-idle-pool-size", "4"})

	if cfg.IdlePoolSize != 4 {
		t.Errorf("Expected --ldap-idle-pool-size=4, got value=%v", cfg.IdlePoolSize)
	}
}

func TestConfigEnvLdapConfIdlePoolSize(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:                     testValueTrue,
		"GEOIPPOLICYD_LDAP_IDLE_POOL_SIZE": "4",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.IdlePoolSize != 4 {
		t.Errorf("Expected --ldap-idle-pool-size=4, got value=%v", cfg.IdlePoolSize)
	}
}

func TestConfigLdapConfPoolSize(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-pool-size", testValueHundred})

	if cfg.PoolSize != 100 {
		t.Errorf("Expected --ldap-pool-size=100, got value=%v", cfg.PoolSize)
	}
}

func TestConfigEnvLdapConfPoolSize(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:                testValueTrue,
		"GEOIPPOLICYD_LDAP_POOL_SIZE": testValueHundred,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.PoolSize != 100 {
		t.Errorf("Expected --ldap-pool-size=100, got value=%v", cfg.PoolSize)
	}
}

func TestConfigEnvLdapConfStartTLS(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:               testValueTrue,
		"GEOIPPOLICYD_LDAP_STARTTLS": testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.StartTLS != true {
		t.Errorf("Expected --ldap-starttls, got value=%v", cfg.StartTLS)
	}
}

func TestConfigLdapConfTLSSkipVerify(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-tls-skip-verify"})

	if cfg.TLSSkipVerify != true {
		t.Errorf("Expected --ldap-tls-skip-verify, got value=%v", cfg.TLSSkipVerify)
	}
}

func TestConfigEnvLdapConfTLSSkipVerify(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:                      testValueTrue,
		"GEOIPPOLICYD_LDAP_TLS_SKIP_VERIFY": testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.TLSSkipVerify != true {
		t.Errorf("Expected --ldap-tls-skip-verify, got value=%v", cfg.TLSSkipVerify)
	}
}

func TestConfigLdapConfTLSClientCert(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-tls-client-cert", testPathTmp})

	if cfg.TLSClientCert != testPathTmp {
		t.Errorf("Expected --ldap-tls-client-cert=/tmp, got value=%v", cfg.TLSClientCert)
	}
}

func TestConfigEnvLdapConfTLSClientCert(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:                      testValueTrue,
		"GEOIPPOLICYD_LDAP_TLS_CLIENT_CERT": testPathTmp,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.TLSClientCert != testPathTmp {
		t.Errorf("Expected --ldap-tls-client-cert=/tmp, got value=%v", cfg.TLSClientCert)
	}
}

func TestConfigLdapConfTLSClientKey(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-tls-client-key", testPathTmp})

	if cfg.TLSClientKey != testPathTmp {
		t.Errorf("Expected --ldap-tls-client-key=/tmp, got value=%v", cfg.TLSClientKey)
	}
}

func TestConfigEnvLdapConfTLSClientKey(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:                     testValueTrue,
		"GEOIPPOLICYD_LDAP_TLS_CLIENT_KEY": testPathTmp,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.TLSClientKey != testPathTmp {
		t.Errorf("Expected --ldap-tls-client-key=/tmp, got value=%v", cfg.TLSClientKey)
	}
}

func TestConfigLdapConfSASLExternal(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, "--ldap-sasl-external"})

	if cfg.SASLExternal != true {
		t.Errorf("Expected --ldap-sasl-external, got value=%v", cfg.SASLExternal)
	}
}

func TestConfigEnvLdapConfSASLExternal(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:                    testValueTrue,
		"GEOIPPOLICYD_LDAP_SASL_EXTERNAL": testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.SASLExternal != true {
		t.Errorf("Expected --ldap-sasl-external, got value=%v", cfg.SASLExternal)
	}
}

func TestConfigLdapConfScopeBase(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, testFlagLDAPScope, BASE})

	if cfg.Scope != ldap.ScopeBaseObject {
		t.Errorf("Expected --ldap-scope=base (%d), got value=%v", ldap.ScopeBaseObject, cfg.Scope)
	}
}

func TestConfigEnvLdapConfScopeBase(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:   testValueTrue,
		testEnvLDAPScope: "base",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.Scope != ldap.ScopeBaseObject {
		t.Errorf("Expected --ldap-scope=base (%d), got value=%v", ldap.ScopeBaseObject, cfg.Scope)
	}
}

func TestConfigLdapConfScopeOne(t *testing.T) {
	cfg := CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, testFlagLDAPScope, ONE})

	if cfg.Scope != ldap.ScopeSingleLevel {
		t.Errorf("Expected --ldap-scope=one (%d), got value=%v", ldap.ScopeSingleLevel, cfg.Scope)
	}
}

func TestConfigEnvLdapConfScopeOne(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:   testValueTrue,
		testEnvLDAPScope: "one",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.Scope != ldap.ScopeSingleLevel {
		t.Errorf("Expected --ldap-scope=one (%d), got value=%v", ldap.ScopeSingleLevel, cfg.Scope)
	}
}

func TestConfigLdapConfScopeSub(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagUseLDAP, testFlagLDAPScope, SUB})

	if cfg.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("Expected --ldap-scope=sub (%d), got value=%v", ldap.ScopeWholeSubtree, cfg.Scope)
	}
}

func TestConfigEnvLdapConfScopeSub(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvUseLDAP:   testValueTrue,
		testEnvLDAPScope: "sub",
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("Expected --ldap-scope=sub (%d), got value=%v", ldap.ScopeWholeSubtree, cfg.Scope)
	}
}

func TestConfigRunActions(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagRunActions})

	if cfg.RunActions != true {
		t.Errorf("Expected --run-actions, got value=%v", cfg.RunActions)
	}
}

func TestConfigEnvRunActions(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvRunActions: testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RunActions != true {
		t.Errorf("Expected --run-actions, got value=%v", cfg.RunActions)
	}
}

func TestConfigRunActionOperator(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagRunActions, testFlagRunActionOperator})

	if cfg.RunActionOperator != true {
		t.Errorf("Expected --run-action-operator, got value=%v", cfg.RunActionOperator)
	}
}

func TestConfigEnvRunActionOperator(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvRunActions:        testValueTrue,
		testEnvRunActionOperator: testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.RunActionOperator != true {
		t.Errorf("Expected --run-action-operator, got value=%v", cfg.RunActionOperator)
	}
}

func TestConfigOperatorTo(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagRunActions, testFlagRunActionOperator, "--operator-to", testValueGeneric})

	if cfg.EmailOperatorTo != testValueGeneric {
		t.Errorf("Expected --operator-to=test, got value=%v", cfg.EmailOperatorTo)
	}
}

func TestConfigEnvOperatorTo(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvRunActions:          testValueTrue,
		testEnvRunActionOperator:   testValueTrue,
		"GEOIPPOLICYD_OPERATOR_TO": testValueGeneric,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.EmailOperatorTo != testValueGeneric {
		t.Errorf("Expected --operator-to=test, got value=%v", cfg.EmailOperatorTo)
	}
}

func TestConfigOperatorFrom(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagRunActions, testFlagRunActionOperator, "--operator-from", testValueGeneric})

	if cfg.EmailOperatorFrom != testValueGeneric {
		t.Errorf("Expected --operator-from=test, got value=%v", cfg.EmailOperatorFrom)
	}
}

func TestConfigEnvOperatorFrom(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvRunActions:            testValueTrue,
		testEnvRunActionOperator:     testValueTrue,
		"GEOIPPOLICYD_OPERATOR_FROM": testValueGeneric,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.EmailOperatorFrom != testValueGeneric {
		t.Errorf("Expected --operator-from=test, got value=%v", cfg.EmailOperatorFrom)
	}
}

func TestConfigOperatorSubject(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagRunActions, testFlagRunActionOperator, "--operator-subject", testValueGeneric})

	if cfg.EmailOperatorSubject != testValueGeneric {
		t.Errorf("Expected --operator-subject=test, got value=%v", cfg.EmailOperatorSubject)
	}
}

func TestConfigEnvOperatorSubject(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvRunActions:               testValueTrue,
		testEnvRunActionOperator:        testValueTrue,
		"GEOIPPOLICYD_OPERATOR_SUBJECT": testValueGeneric,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.EmailOperatorSubject != testValueGeneric {
		t.Errorf("Expected --operator-subject=test, got value=%v", cfg.EmailOperatorSubject)
	}
}

func TestConfigOperatorMessageCT(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagRunActions, testFlagRunActionOperator, "--operator-message-ct", testTextHTML})

	if cfg.EmailOperatorMessageCT != testTextHTML {
		t.Errorf("Expected --operator-message-ct=text/html, got value=%v", cfg.EmailOperatorMessageCT)
	}
}

func TestConfigEnvOperatorMessageCT(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvRunActions:                  testValueTrue,
		testEnvRunActionOperator:           testValueTrue,
		"GEOIPPOLICYD_OPERATOR_MESSAGE_CT": testTextHTML,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.EmailOperatorMessageCT != testTextHTML {
		t.Errorf("Expected --operator-message-ct=text/html, got value=%v", cfg.EmailOperatorMessageCT)
	}
}

func TestConfigOperatorMessagePath(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagRunActions, testFlagRunActionOperator, "--operator-message-path", testPathTmp})

	if cfg.EmailOperatorMessagePath != testPathTmp {
		t.Errorf("Expected --operator-message-path=/tmp, got value=%v", cfg.EmailOperatorMessagePath)
	}
}

func TestConfigEnvOperatorMessagePath(t *testing.T) {
	closer := envSetter(map[string]string{
		testEnvRunActions:                    testValueTrue,
		testEnvRunActionOperator:             testValueTrue,
		"GEOIPPOLICYD_OPERATOR_MESSAGE_PATH": testPathTmp,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.EmailOperatorMessagePath != testPathTmp {
		t.Errorf("Expected --operator-message-path=/tmp, got value=%v", cfg.EmailOperatorMessagePath)
	}
}

func TestConfigMailServerAddress(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--mail-server-address", testMailHost})

	if cfg.MailServer != testMailHost {
		t.Errorf("Expected --mail-server-address=mail.google.com, got value=%v", cfg.MailServer)
	}
}

func TestConfigEnvMailServerAddress(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_SERVER_ADDRESS": testMailHost,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MailServer != testMailHost {
		t.Errorf("Expected --mail-server-address=mail.google.com, got value=%v", cfg.MailServer)
	}
}

func TestConfigMailHelo(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--mail-helo", testMailHeloHost})

	if cfg.MailHelo != testMailHeloHost {
		t.Errorf("Expected --mail-helo=localhost.localdomain, got value=%v", cfg.MailHelo)
	}
}

func TestConfigEnvMailHelo(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_HELO": testMailHeloHost,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MailHelo != testMailHeloHost {
		t.Errorf("Expected --mail-helo=localhost.localdomain, got value=%v", cfg.MailHelo)
	}
}

func TestConfigMailPort(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--mail-server-port", "465"})

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
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MailPort != 465 {
		t.Errorf("Expected --mail-server-port=465, got value=%v", cfg.MailPort)
	}
}

func TestConfigMailUsername(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--mail-username", testValueUsername})

	if cfg.MailUsername != testValueUsername {
		t.Errorf("Expected --mail-username=username, got value=%v", cfg.MailUsername)
	}
}

func TestConfigEnvMailUsername(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_USERNAME": testValueUsername,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MailUsername != testValueUsername {
		t.Errorf("Expected --mail-username=username, got value=%v", cfg.MailUsername)
	}
}

func TestConfigMailPassword(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--mail-password", testValuePassword})

	if cfg.MailPassword != testValuePassword {
		t.Errorf("Expected --mail-password=password, got value=%v", cfg.MailPassword)
	}
}

func TestConfigEnvMailPassword(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_PASSWORD": testValuePassword,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MailPassword != testValuePassword {
		t.Errorf("Expected --mail-password=password, got value=%v", cfg.MailPassword)
	}
}

func TestConfigMailSSL(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, "--mail-ssl-on-connect"})

	if cfg.MailSSL != true {
		t.Errorf("Expected --mail-ssl-on-connect, got value=%v", cfg.MailSSL)
	}
}

func TestConfigEnvMailSSL(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_MAIL_SSL_ON_CONNECT": testValueTrue,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.MailSSL != true {
		t.Errorf("Expected --mail-ssl, got value=%v", cfg.MailSSL)
	}
}

func TestConfigObservabilityDefaults(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if cfg.Observability.PrometheusEnabled {
		t.Fatal("PrometheusEnabled = true, want false")
	}

	if cfg.Observability.PrometheusPath != prometheusPath {
		t.Fatalf("PrometheusPath = %q, want %s", cfg.Observability.PrometheusPath, prometheusPath)
	}

	if !cfg.Observability.PrometheusRuntimeMetrics {
		t.Fatal("PrometheusRuntimeMetrics = false, want true")
	}

	if cfg.Observability.OTelEnabled {
		t.Fatal("OTelEnabled = true, want false")
	}

	if !cfg.Observability.OTelTracesEnabled {
		t.Fatal("OTelTracesEnabled = false, want true")
	}

	if cfg.Observability.OTelMetricsEnabled {
		t.Fatal("OTelMetricsEnabled = true, want false")
	}

	if cfg.Observability.OTelServiceName != otelService {
		t.Fatalf("OTelServiceName = %q, want %s", cfg.Observability.OTelServiceName, otelService)
	}

	if cfg.Observability.OTelSampleRatio != 1.0 {
		t.Fatalf("OTelSampleRatio = %v, want 1.0", cfg.Observability.OTelSampleRatio)
	}

	if !cfg.Observability.OTLPInsecure {
		t.Fatal("OTLPInsecure = false, want true")
	}
}

func TestConfigPrometheusObservability(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{
		testCommandApp, testCommandServer,
		"--prometheus-enabled",
		"--prometheus-path", testPrometheusMetrics,
		"--prometheus-runtime-metrics=" + testBooleanFalse,
	})

	if !cfg.Observability.PrometheusEnabled {
		t.Fatal("PrometheusEnabled = false, want true")
	}

	if cfg.Observability.PrometheusPath != testPrometheusMetrics {
		t.Fatalf("PrometheusPath = %q, want /internal/metrics", cfg.Observability.PrometheusPath)
	}

	if cfg.Observability.PrometheusRuntimeMetrics {
		t.Fatal("PrometheusRuntimeMetrics = true, want false")
	}
}

func TestConfigEnvPrometheusObservability(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_PROMETHEUS_ENABLED":         testValueTrue,
		"GEOIPPOLICYD_PROMETHEUS_PATH":            testPrometheusMetrics,
		"GEOIPPOLICYD_PROMETHEUS_RUNTIME_METRICS": testBooleanFalse,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if !cfg.Observability.PrometheusEnabled {
		t.Fatal("PrometheusEnabled = false, want true")
	}

	if cfg.Observability.PrometheusPath != testPrometheusMetrics {
		t.Fatalf("PrometheusPath = %q, want /internal/metrics", cfg.Observability.PrometheusPath)
	}

	if cfg.Observability.PrometheusRuntimeMetrics {
		t.Fatal("PrometheusRuntimeMetrics = true, want false")
	}
}

func TestConfigOpenTelemetryObservability(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{
		testCommandApp, testCommandServer,
		testOTelEnabledFlag,
		"--otel-traces-enabled=" + testBooleanFalse,
		"--otel-metrics-enabled",
		"--otel-service-name", testOTelService,
		"--otel-service-version", testOTelVersion,
		"--otel-exporter-otlp-endpoint", testOTLPEndpoint,
		"--otel-exporter-otlp-headers", testOTLPHeaders,
		"--otel-exporter-otlp-insecure=" + testBooleanFalse,
		"--otel-sample-ratio", testOTLPSampleRatio,
	})

	if !cfg.Observability.OTelEnabled {
		t.Fatal("OTelEnabled = false, want true")
	}

	if cfg.Observability.OTelTracesEnabled {
		t.Fatal("OTelTracesEnabled = true, want false")
	}

	if !cfg.Observability.OTelMetricsEnabled {
		t.Fatal("OTelMetricsEnabled = false, want true")
	}

	if cfg.Observability.OTelServiceName != testOTelService {
		t.Fatalf("OTelServiceName = %q, want geoip-policyd-test", cfg.Observability.OTelServiceName)
	}

	if cfg.Observability.OTelServiceVersion != testOTelVersion {
		t.Fatalf("OTelServiceVersion = %q, want test-version", cfg.Observability.OTelServiceVersion)
	}

	if cfg.Observability.OTLPEndpoint != testOTLPEndpoint {
		t.Fatalf("OTLPEndpoint = %q, want http://collector.example:4318", cfg.Observability.OTLPEndpoint)
	}

	if cfg.Observability.OTLPHeaders["tenant"] != testLDAPResultAttribute || cfg.Observability.OTLPHeaders["token"] != testOTLPSecret {
		t.Fatalf("OTLPHeaders = %#v, want tenant and token entries", cfg.Observability.OTLPHeaders)
	}

	if cfg.Observability.OTLPInsecure {
		t.Fatal("OTLPInsecure = true, want false")
	}

	if cfg.Observability.OTelSampleRatio != 0.25 {
		t.Fatalf("OTelSampleRatio = %v, want 0.25", cfg.Observability.OTelSampleRatio)
	}
}

func TestConfigOpenTelemetryMetricsOptIn(t *testing.T) {
	cfg := &CmdLineConfig{}
	cfg.Init([]string{
		testCommandApp, testCommandServer,
		testOTelEnabledFlag,
		"--otel-exporter-otlp-endpoint", testOTLPEndpoint,
	})

	if !cfg.Observability.OTelEnabled {
		t.Fatal("OTelEnabled = false, want true")
	}

	if !cfg.Observability.OTelTracesEnabled {
		t.Fatal("OTelTracesEnabled = false, want true")
	}

	if cfg.Observability.OTelMetricsEnabled {
		t.Fatal("OTelMetricsEnabled = true, want false")
	}
}

func TestConfigEnvOpenTelemetryObservability(t *testing.T) {
	closer := envSetter(map[string]string{
		"GEOIPPOLICYD_OTEL_ENABLED":                testValueTrue,
		"GEOIPPOLICYD_OTEL_TRACES_ENABLED":         testBooleanFalse,
		"GEOIPPOLICYD_OTEL_METRICS_ENABLED":        testValueTrue,
		"GEOIPPOLICYD_OTEL_SERVICE_NAME":           testOTelService,
		"GEOIPPOLICYD_OTEL_SERVICE_VERSION":        testOTelVersion,
		"GEOIPPOLICYD_OTEL_EXPORTER_OTLP_ENDPOINT": testOTLPEndpoint,
		"GEOIPPOLICYD_OTEL_EXPORTER_OTLP_HEADERS":  testOTLPHeaders,
		"GEOIPPOLICYD_OTEL_EXPORTER_OTLP_INSECURE": testBooleanFalse,
		"GEOIPPOLICYD_OTEL_SAMPLE_RATIO":           testOTLPSampleRatio,
	})
	defer closer()

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer})

	if !cfg.Observability.OTelEnabled {
		t.Fatal("OTelEnabled = false, want true")
	}

	if cfg.Observability.OTelTracesEnabled {
		t.Fatal("OTelTracesEnabled = true, want false")
	}

	if !cfg.Observability.OTelMetricsEnabled {
		t.Fatal("OTelMetricsEnabled = false, want true")
	}

	if cfg.Observability.OTelServiceName != testOTelService {
		t.Fatalf("OTelServiceName = %q, want geoip-policyd-test", cfg.Observability.OTelServiceName)
	}

	if cfg.Observability.OTelServiceVersion != testOTelVersion {
		t.Fatalf("OTelServiceVersion = %q, want test-version", cfg.Observability.OTelServiceVersion)
	}

	if cfg.Observability.OTLPEndpoint != testOTLPEndpoint {
		t.Fatalf("OTLPEndpoint = %q, want http://collector.example:4318", cfg.Observability.OTLPEndpoint)
	}

	if cfg.Observability.OTLPHeaders["tenant"] != testLDAPResultAttribute || cfg.Observability.OTLPHeaders["token"] != testOTLPSecret {
		t.Fatalf("OTLPHeaders = %#v, want tenant and token entries", cfg.Observability.OTLPHeaders)
	}

	if cfg.Observability.OTLPInsecure {
		t.Fatal("OTLPInsecure = true, want false")
	}

	if cfg.Observability.OTelSampleRatio != 0.25 {
		t.Fatalf("OTelSampleRatio = %v, want 0.25", cfg.Observability.OTelSampleRatio)
	}
}

func TestValidateOpenTelemetryRequiresEndpoint(t *testing.T) {
	geoIPFile, err := os.CreateTemp(t.TempDir(), "geoip-*.mmdb")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}

	if err = geoIPFile.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	cfg := &CmdLineConfig{}
	cfg.Init([]string{testCommandApp, testCommandServer, testFlagGeoIPPath, geoIPFile.Name(), testOTelEnabledFlag})

	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want missing OTLP endpoint error")
	}

	if !strings.Contains(err.Error(), "otel-exporter-otlp-endpoint") {
		t.Fatalf("Validate() error = %q, want otel-exporter-otlp-endpoint", err.Error())
	}
}
