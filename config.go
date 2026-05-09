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
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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
	prometheusPath = "/metrics"
	otelService    = "geoip-policyd"
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
	ServerAddress string `validate:"ip|hostname_rfc1123"`

	// Prt number for the policy service
	ServerPort int `validate:"min=1,max=65535"`

	// REST interface of the policy service
	HTTPAddress string `validate:"ip|hostname_rfc1123"`
	HTTPPort    int    `validate:"min=1,max=65535"`
	HTTPApp

	// Use 'sender' or 'sasl_username' attribute?
	UseSASLUsername bool

	// Redis settings for a reading and/or writing server pool
	RedisAddress  string `validate:"ip|hostname_rfc1123"`
	RedisPort     int    `validate:"min=1,max=65535"`
	RedisUsername string
	RedisPassword string

	// Redis for a replica (read-only) server pool
	RedisAddressRO string `validate:"ip|hostname_rfc1123"`
	RedisPortRO    int    `validate:"min=1,max=65535"`

	RedisSentinels          []string
	RedisSentinelMasterName string
	RedisSentinelUsername   string
	RedisSentinelPassword   string

	RedisPrefix string `validate:"required"`
	RedisDB     int    `validate:"min=0"`
	RedisTTL    int    `validate:"min=0"`

	GeoipPath        string   `validate:"required,file"`
	MaxCountries     int      `validate:"min=0"`
	MaxIPs           int      `validate:"min=0"`
	HomeCountries    []string `validate:"dive,iso3166_1_alpha2"`
	MaxHomeCountries int      `validate:"min=0"`
	MaxHomeIPs       int      `validate:"min=0"`
	IgnoreNets       []string `validate:"dive,cidr_or_ip"`
	BlockPermanent   bool
	VerboseLevel     int

	// Flag that indicates which command was called
	CommandServer bool

	UseCDB  bool
	CDBPath string `validate:"required_if=UseCDB true,omitempty,file"`

	UseLDAP bool
	*LdapConf

	LogFormatJSON      bool
	CustomSettingsPath string `validate:"omitempty,file"`

	// Global flag that indicates if any action should be taken
	RunActions bool

	// Flag that indicates, if the operator action should be taken
	RunActionOperator bool

	// Action that sends a notification to an operator
	EmailOperatorTo          string `validate:"required_if=RunActionOperator true,omitempty,email"`
	EmailOperatorFrom        string `validate:"required_if=RunActionOperator true,omitempty,email"`
	EmailOperatorSubject     string
	EmailOperatorMessageCT   string
	EmailOperatorMessagePath string `validate:"required_if=RunActionOperator true,omitempty,file"`

	// Global mail server configuration parameters
	MailServer   string
	MailHelo     string
	MailPort     int `validate:"min=1,max=65535"`
	MailUsername string
	MailPassword string
	MailSSL      bool

	// ForceUserKnown represents a boolean flag indicating whether the user is known or not.
	ForceUserKnown bool

	// Observability contains Prometheus and OpenTelemetry runtime settings.
	Observability ObservabilityConfig

	// policySettings caches policy limits and matchers derived from static configuration.
	policySettings *PolicySettings
	// ignoreNetworkMatcher caches parsed ignore-network entries for request-time checks.
	ignoreNetworkMatcher *NetworkMatcher
	// observabilityRuntime owns metrics, tracing providers, and shutdown behavior.
	observabilityRuntime *Observability
}

// ObservabilityConfig contains Prometheus and OpenTelemetry operator settings.
type ObservabilityConfig struct {
	PrometheusEnabled        bool
	PrometheusPath           string
	PrometheusRuntimeMetrics bool

	OTelEnabled        bool
	OTelTracesEnabled  bool
	OTelMetricsEnabled bool
	OTelServiceName    string
	OTelServiceVersion string
	OTLPEndpoint       string
	OTLPHeaders        map[string]string
	OTLPInsecure       bool
	OTelSampleRatio    float64
}

type CustomSettings struct {
	Data []Account `json:"data"`
	// compiled indexes account-specific settings by sender for request-time lookups.
	compiled map[string]*CompiledAccountSettings
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
	var result strings.Builder

	value := reflect.ValueOf(*c)
	typeOfC := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfC.Field(index).Name {
		case "CommandServer", "UseLDAP", "LDAP", "MailPassword", "HTTPApp", "VerboseLevel", "Observability", "policySettings", "ignoreNetworkMatcher", "observabilityRuntime":
			continue
		default:
			_, _ = fmt.Fprintf(&result, " %s='%v'", typeOfC.Field(index).Name, value.Field(index).Interface())
		}
	}

	return result.String()[1:]
}

// splitComma splits a comma-separated string into a trimmed slice, returning nil for empty input.
func splitComma(s string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}

	return parts
}

// parseOTLPHeaders converts comma-separated key=value pairs into OTLP HTTP headers.
func parseOTLPHeaders(raw string) map[string]string {
	headers := make(map[string]string)
	if raw == "" {
		return headers
	}

	for part := range strings.SplitSeq(raw, ",") {
		keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		if key == "" {
			continue
		}

		headers[key] = value
	}

	return headers
}

//nolint:gocognit,gocyclo,maintidx // Ignore complexity
func (c *CmdLineConfig) Init(args []string) {
	// Detect "server" subcommand (must appear before any flags).
	subCmdIdx := -1

	for i := 1; i < len(args); i++ {
		if args[i] == "server" {
			subCmdIdx = i

			break
		}

		if strings.HasPrefix(args[i], "-") {
			break
		}
	}

	c.CommandServer = subCmdIdx >= 0

	// Create a unified pflag FlagSet for all flags.
	flags := pflag.NewFlagSet(args[0], pflag.ContinueOnError)

	// Root flags
	argVerbose := flags.CountP("verbose", "v", "Verbose mode. Repeat this for an increased log level")
	argVersion := flags.Bool("version", false, "Current version")

	/*
	 * GeoIP policy server options
	 */
	argServerAddress := flags.StringP("server-address", "a", serverAddress, "IPv4 or IPv6 address for the policy service")
	argServerPort := flags.IntP("server-port", "p", serverPort, "Port for the policy service")
	argServerHTTPAddress := flags.String("http-address", httpAddress, "HTTP address for incoming requests")
	argHTTPPort := flags.Int("http-port", httpPort, "HTTP port for incoming requests")
	argServerUseSASLUsername := flags.Bool("sasl-username", false, "Use 'sasl_username' instead of the 'sender' attribute")

	/*
	 * Redis options for read and/or write requests
	 */
	argServerRedisAddress := flags.StringP("redis-address", "A", redisAddress, "IPv4 or IPv6 address for the Redis service")
	argServerRedisPort := flags.IntP("redis-port", "P", redisPort, "Port for the Redis service")
	argServerRedisDB := flags.Int("redis-database-number", 0, "Redis database number")
	argServerRedisUsername := flags.String("redis-username", "", "Redis username")
	argServerRedisPassword := flags.String("redis-password", "", "Redis password")

	/*
	 * Redis options for replica (read-only) requests
	 */
	argServerRedisAddressRO := flags.String("redis-replica-address", redisAddress, "IPv4 or IPv6 address for a Redis service (replica)")
	argServerRedisPortRO := flags.Int("redis-replica-port", redisPort, "Port for a Redis service (replica)")

	/*
	 * Common Redis options
	 */
	argServerRedisSentinels := flags.StringArray("redis-sentinels", []string{}, "List of space separated sentinel servers")
	argServerRedisSentinelMasterName := flags.String("redis-sentinel-master-name", "", "Sentinel master name")
	argServerRedisSentinelUsername := flags.String("redis-sentinel-username", "", "Redis sentinel username")
	argServerRedisSentinelPassword := flags.String("redis-sentinel-password", "", "Redis sentinel password")
	argServerRedisPrefix := flags.String("redis-prefix", redisPrefix, "Redis prefix")
	argServerRedisTTL := flags.Int("redis-ttl", redisTTL, "Redis TTL in seconds")

	/*
	 * Other config options
	 */
	argServerGeoIPDB := flags.StringP("geoip-path", "g", geoipPath, "Full path to the GeoIP database file")
	argServerMaxCountries := flags.Int("max-countries", maxCountries, "Maximum number of countries before rejecting e-mails")
	argServerMaxIPs := flags.Int("max-ips", maxIPs, "Maximum number of IP addresses before rejecting e-mails")
	argServerHomeCountries := flags.StringArray("home-countries", []string{}, "List of known home country codes")
	argServerMaxHomeCountries := flags.Int("max-home-countries", maxCountries, "Maximum number home of countries before rejecting e-mails")
	argServerMaxHomeIPs := flags.Int("max-home-ips", maxIPs, "Maximum number of home IP addresses before rejecting e-mails")
	argServerIgnoreNets := flags.StringArray("ignore-network", []string{}, "List of IP addresses and networks to ignore")
	argServerBlockedNoExpire := flags.Bool("block-permanent", false, "Do not expire senders from Redis, if they were blocked in the past")
	argServerForceUserKnown := flags.Bool("force-user-known", false, "Senders are already known by an upstream service")
	argServerCustomSettingsPath := flags.StringP("custom-settings-path", "c", "", "Custom settings with different IP and country limits")
	argServerHTTPUseBasicAuth := flags.Bool("http-use-basic-auth", false, "Enable basic HTTP auth")
	argServerHTTPUseSSL := flags.Bool("http-use-ssl", false, "Enable HTTPS")
	argServerHTTPBasicAuthUsername := flags.String("http-basic-auth-username", "", "HTTP basic auth username")
	argServerHTTPBasicAuthPassword := flags.String("http-basic-auth-password", "", "HTTP basic auth password")
	argServerHTTPTLSCert := flags.String("http-tls-cert", httpX509Cert, "HTTP TLS server certificate (full chain)")
	argServerHTTPTLSKey := flags.String("http-tls-key", httpX509Key, "HTTP TLS server key")
	argServerPrometheusEnabled := flags.Bool("prometheus-enabled", false, "Enable Prometheus metrics on the HTTP service")
	argServerPrometheusPath := flags.String("prometheus-path", prometheusPath, "HTTP path for Prometheus metrics")
	argServerPrometheusRuntimeMetrics := flags.Bool("prometheus-runtime-metrics", true, "Include Go runtime and process metrics")
	argServerOTelEnabled := flags.Bool("otel-enabled", false, "Enable OpenTelemetry export")
	argServerOTelTracesEnabled := flags.Bool("otel-traces-enabled", true, "Export OpenTelemetry traces when OTel is enabled")
	argServerOTelMetricsEnabled := flags.Bool("otel-metrics-enabled", true, "Export OpenTelemetry metrics when OTel is enabled")
	argServerOTelServiceName := flags.String("otel-service-name", otelService, "OpenTelemetry service.name resource attribute")
	argServerOTelServiceVersion := flags.String("otel-service-version", "", "OpenTelemetry service.version resource attribute")
	argServerOTLPEndpoint := flags.String("otel-exporter-otlp-endpoint", "", "OTLP HTTP endpoint URL")
	argServerOTLPHeaders := flags.String("otel-exporter-otlp-headers", "", "Comma-separated OTLP HTTP headers as key=value pairs")
	argServerOTLPInsecure := flags.Bool("otel-exporter-otlp-insecure", true, "Use insecure OTLP HTTP transport")
	argServerOTelSampleRatio := flags.Float64("otel-sample-ratio", 1.0, "OpenTelemetry trace sampling ratio between 0.0 and 1.0")
	argServerUseCDB := flags.Bool("use-cdb", false, "Enable CDB support")
	argServerCDBPath := flags.String("cdb-path", "", "Full path to the cdb file")
	argServerUseLDAP := flags.Bool("use-ldap", false, "Enable LDAP support")
	argServerLDAPServerURIs := flags.StringArray("ldap-server-uri", []string{"ldap://127.0.0.1:389/"}, "Server URI. Specify multiple times, if you need more than one server")
	argServerLDAPBaseDN := flags.String("ldap-basedn", "", "Base DN")
	argServerLDAPBindDN := flags.String("ldap-binddn", "", "bind DN")
	argServerLDAPBindPWPATH := flags.String("ldap-bindpw", "", "bind password")
	argServerLDAPFilter := flags.String("ldap-filter", "(&(objectClass=*)(mailAlias=%s))", "Filter with %s placeholder")
	argServerLDAPResultAttr := flags.String("ldap-result-attribute", "mailAccount", "Result attribute for the requested mail sender")
	argServerLDAPStartTLS := flags.Bool("ldap-starttls", false, "If this option is given, use StartTLS")
	argServerLDAPTLSVerify := flags.Bool("ldap-tls-skip-verify", false, "Skip TLS server name verification")
	argServerLDAPTLSCAFile := flags.String("ldap-tls-cafile", "", "File containing TLS CA certificate(s)")
	argServerLDAPTLSClientCert := flags.String("ldap-tls-client-cert", "", "File containing a TLS client certificate")
	argServerLDAPTLSClientKey := flags.String("ldap-tls-client-key", "", "File containing a TLS client key")
	argServerLDAPSASLExternal := flags.Bool("ldap-sasl-external", false, "Use SASL/EXTERNAL instead of a simple bind")
	argServerLDAPScope := flags.String("ldap-scope", "sub", "LDAP search scope [base, one, sub]")
	argServerLDAPIdlePoolSize := flags.Int("ldap-idle-pool-size", int(ldapPoolSize*0.3), "LDAP pre-forked (idle) pool size")
	argServerLDAPPoolSize := flags.Int("ldap-pool-size", ldapPoolSize, "LDAP max pool size")
	argServerLogFormatJSON := flags.Bool("log-json", false, "Enable JSON log format")
	argServerRunActions := flags.Bool("run-actions", false, "Run actions, if a sender is over limits")
	argServerRunActionOperator := flags.Bool("run-action-operator", false, "Run the operator action")
	argServerOperatorTo := flags.String("operator-to", "", "E-Mail To-header for the operator action")
	argServerOperatorFrom := flags.String("operator-from", "", "E-Mail From-header for the operator action")
	argServerOperatorSubject := flags.String("operator-subject", mailSubject, "E-Mail Subject-header for the operator action")
	argServerOperatorMessageCT := flags.String("operator-message-ct", "text/plain", "E-Mail Content-Type-header for the operator action")
	argServerOperatorMessagePath := flags.String("operator-message-path", "", "Full path to the e-mail message file for the operator action")
	argServerMailServer := flags.String("mail-server-address", "", "E-mail server address for notifications")
	argServerMailPort := flags.Int("mail-server-port", mailPort, "E-mail server port number")
	argServerMailHelo := flags.String("mail-helo", mailHelo, "E-mail server HELO/EHLO hostname")
	argServerMailUsername := flags.String("mail-username", "", "E-mail server username")
	argServerMailPasswordPath := flags.String("mail-password", "", "E-mail server password")
	argServerMailSSL := flags.Bool("mail-ssl-on-connect", false, "Use SSL/TLS on connect for the e-mail server")

	// Parse flags from args following the optional subcommand.
	var parseArgs []string
	if subCmdIdx >= 0 {
		parseArgs = args[subCmdIdx+1:]
	} else {
		parseArgs = args[1:]
	}

	if err := flags.Parse(parseArgs); err != nil {
		log.Fatalln(err)
	}

	if *argVersion {
		fmt.Println("Version:", version) //nolint:forbidigo // Printing a version number is okay
		os.Exit(0)
	}

	// Cap idle pool size to pool size (CLI values only; env vars are not capped).
	if *argServerLDAPIdlePoolSize > *argServerLDAPPoolSize {
		*argServerLDAPIdlePoolSize = *argServerLDAPPoolSize
	}

	// ---------------------------------------------------------------------------
	// Viper: env vars override CLI defaults. Priority: env var > CLI arg > built-in default.
	// Env var names are derived automatically: key "server_address" → GEOIPPOLICYD_SERVER_ADDRESS.
	// ---------------------------------------------------------------------------
	v := viper.New()
	v.SetEnvPrefix("GEOIPPOLICYD")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// --- Verbose level (special: string none/info/debug → int) ---
	var verbDefault string

	switch *argVerbose {
	case logLevelNone:
		verbDefault = "none"
	case logLevelInfo:
		verbDefault = "info"
	case logLevelDebug:
		verbDefault = "debug"
	default:
		verbDefault = "info"
	}

	v.SetDefault("verbose_level", verbDefault)

	switch v.GetString("verbose_level") {
	case "none":
		c.VerboseLevel = logLevelNone
	case "info":
		c.VerboseLevel = logLevelInfo
	case "debug":
		c.VerboseLevel = logLevelDebug
	}

	// --- Log format JSON ---
	v.SetDefault("log_json", *argServerLogFormatJSON)
	c.LogFormatJSON = v.GetBool("log_json")

	if c.CommandServer {
		// --- Server ---
		v.SetDefault("server_address", *argServerAddress)
		c.ServerAddress = v.GetString("server_address")

		v.SetDefault("server_port", *argServerPort)
		c.ServerPort = v.GetInt("server_port")

		v.SetDefault("http_address", *argServerHTTPAddress)
		c.HTTPAddress = v.GetString("http_address")

		v.SetDefault("http_port", *argHTTPPort)
		c.HTTPPort = v.GetInt("http_port")

		v.SetDefault("use_sasl_username", *argServerUseSASLUsername)
		c.UseSASLUsername = v.GetBool("use_sasl_username")

		// --- Redis (read/write) ---
		v.SetDefault("redis_address", *argServerRedisAddress)
		c.RedisAddress = v.GetString("redis_address")

		v.SetDefault("redis_port", *argServerRedisPort)
		c.RedisPort = v.GetInt("redis_port")

		v.SetDefault("redis_database_number", *argServerRedisDB)
		c.RedisDB = v.GetInt("redis_database_number")

		v.SetDefault("redis_username", *argServerRedisUsername)
		c.RedisUsername = v.GetString("redis_username")

		v.SetDefault("redis_password", *argServerRedisPassword)
		c.RedisPassword = v.GetString("redis_password")

		// --- Redis replica ---
		v.SetDefault("redis_replica_address", *argServerRedisAddressRO)
		c.RedisAddressRO = v.GetString("redis_replica_address")

		v.SetDefault("redis_replica_port", *argServerRedisPortRO)
		c.RedisPortRO = v.GetInt("redis_replica_port")

		// --- Redis sentinel (space-separated list in env var) ---
		v.SetDefault("redis_sentinels", strings.Join(*argServerRedisSentinels, " "))

		if sentinelsStr := v.GetString("redis_sentinels"); sentinelsStr != "" {
			c.RedisSentinels = strings.Split(sentinelsStr, " ")
		} else {
			c.RedisSentinels = []string{}
		}

		v.SetDefault("redis_sentinel_master_name", *argServerRedisSentinelMasterName)
		c.RedisSentinelMasterName = v.GetString("redis_sentinel_master_name")

		v.SetDefault("redis_sentinel_username", *argServerRedisSentinelUsername)
		c.RedisSentinelUsername = v.GetString("redis_sentinel_username")

		v.SetDefault("redis_sentinel_password", *argServerRedisSentinelPassword)
		c.RedisSentinelPassword = v.GetString("redis_sentinel_password")

		// --- Redis common ---
		v.SetDefault("redis_prefix", *argServerRedisPrefix)
		c.RedisPrefix = v.GetString("redis_prefix")

		v.SetDefault("redis_ttl", *argServerRedisTTL)
		c.RedisTTL = v.GetInt("redis_ttl")

		// --- GeoIP ---
		v.SetDefault("geoip_path", *argServerGeoIPDB)
		c.GeoipPath = v.GetString("geoip_path")

		// --- Country / IP limits ---
		v.SetDefault("max_countries", *argServerMaxCountries)
		c.MaxCountries = v.GetInt("max_countries")

		v.SetDefault("max_ips", *argServerMaxIPs)
		c.MaxIPs = v.GetInt("max_ips")

		// Home countries (space-separated list in env var)
		v.SetDefault("home_countries", strings.Join(*argServerHomeCountries, " "))

		if homeStr := v.GetString("home_countries"); homeStr != "" {
			c.HomeCountries = strings.Split(homeStr, " ")
		} else {
			c.HomeCountries = []string{}
		}

		v.SetDefault("max_home_countries", *argServerMaxHomeCountries)
		c.MaxHomeCountries = v.GetInt("max_home_countries")

		v.SetDefault("max_home_ips", *argServerMaxHomeIPs)
		c.MaxHomeIPs = v.GetInt("max_home_ips")

		// Ignore networks (space-separated list in env var)
		v.SetDefault("ignore_networks", strings.Join(*argServerIgnoreNets, " "))

		if ignoreStr := v.GetString("ignore_networks"); ignoreStr != "" {
			c.IgnoreNets = strings.Split(ignoreStr, " ")
		} else {
			c.IgnoreNets = []string{}
		}

		v.SetDefault("block_permanent", *argServerBlockedNoExpire)
		c.BlockPermanent = v.GetBool("block_permanent")

		v.SetDefault("force_user_known", *argServerForceUserKnown)
		c.ForceUserKnown = v.GetBool("force_user_known")

		v.SetDefault("custom_settings_path", *argServerCustomSettingsPath)
		c.CustomSettingsPath = v.GetString("custom_settings_path")

		// --- HTTP app ---
		v.SetDefault("http_use_basic_auth", *argServerHTTPUseBasicAuth)
		c.HTTPApp.useBasicAuth = v.GetBool("http_use_basic_auth")

		if c.HTTPApp.useBasicAuth {
			v.SetDefault("http_basic_auth_username", *argServerHTTPBasicAuthUsername)
			c.HTTPApp.auth.username = v.GetString("http_basic_auth_username")

			v.SetDefault("http_basic_auth_password", *argServerHTTPBasicAuthPassword)
			c.HTTPApp.auth.password = v.GetString("http_basic_auth_password")
		}

		v.SetDefault("http_use_ssl", *argServerHTTPUseSSL)
		c.HTTPApp.useSSL = v.GetBool("http_use_ssl")

		if c.HTTPApp.useSSL {
			v.SetDefault("http_tls_cert", *argServerHTTPTLSCert)
			c.HTTPApp.x509.cert = v.GetString("http_tls_cert")

			v.SetDefault("http_tls_key", *argServerHTTPTLSKey)
			c.HTTPApp.x509.key = v.GetString("http_tls_key")
		}

		// --- Observability ---
		v.SetDefault("prometheus_enabled", *argServerPrometheusEnabled)
		c.Observability.PrometheusEnabled = v.GetBool("prometheus_enabled")

		v.SetDefault("prometheus_path", *argServerPrometheusPath)
		c.Observability.PrometheusPath = v.GetString("prometheus_path")

		v.SetDefault("prometheus_runtime_metrics", *argServerPrometheusRuntimeMetrics)
		c.Observability.PrometheusRuntimeMetrics = v.GetBool("prometheus_runtime_metrics")

		v.SetDefault("otel_enabled", *argServerOTelEnabled)
		c.Observability.OTelEnabled = v.GetBool("otel_enabled")

		v.SetDefault("otel_traces_enabled", *argServerOTelTracesEnabled)
		c.Observability.OTelTracesEnabled = v.GetBool("otel_traces_enabled")

		v.SetDefault("otel_metrics_enabled", *argServerOTelMetricsEnabled)
		c.Observability.OTelMetricsEnabled = v.GetBool("otel_metrics_enabled")

		v.SetDefault("otel_service_name", *argServerOTelServiceName)
		c.Observability.OTelServiceName = v.GetString("otel_service_name")

		v.SetDefault("otel_service_version", *argServerOTelServiceVersion)
		c.Observability.OTelServiceVersion = v.GetString("otel_service_version")

		v.SetDefault("otel_exporter_otlp_endpoint", *argServerOTLPEndpoint)
		c.Observability.OTLPEndpoint = v.GetString("otel_exporter_otlp_endpoint")

		v.SetDefault("otel_exporter_otlp_headers", *argServerOTLPHeaders)
		c.Observability.OTLPHeaders = parseOTLPHeaders(v.GetString("otel_exporter_otlp_headers"))

		v.SetDefault("otel_exporter_otlp_insecure", *argServerOTLPInsecure)
		c.Observability.OTLPInsecure = v.GetBool("otel_exporter_otlp_insecure")

		v.SetDefault("otel_sample_ratio", *argServerOTelSampleRatio)
		c.Observability.OTelSampleRatio = v.GetFloat64("otel_sample_ratio")

		// --- CDB ---
		v.SetDefault("use_cdb", *argServerUseCDB)
		c.UseCDB = v.GetBool("use_cdb")

		v.SetDefault("cdb_path", *argServerCDBPath)
		c.CDBPath = v.GetString("cdb_path")

		// --- LDAP ---
		v.SetDefault("use_ldap", *argServerUseLDAP)
		c.UseLDAP = v.GetBool("use_ldap")

		if c.UseLDAP {
			c.LdapConf = &LdapConf{}

			// LDAP URIs (comma-separated list in env var)
			v.SetDefault("ldap_server_uris", strings.Join(*argServerLDAPServerURIs, ","))

			if urisStr := v.GetString("ldap_server_uris"); urisStr != "" {
				c.LdapConf.ServerURIs = splitComma(urisStr)
			} else {
				c.LdapConf.ServerURIs = []string{}
			}

			v.SetDefault("ldap_basedn", *argServerLDAPBaseDN)
			c.LdapConf.BaseDN = v.GetString("ldap_basedn")

			v.SetDefault("ldap_binddn", *argServerLDAPBindDN)
			c.LdapConf.BindDN = v.GetString("ldap_binddn")

			v.SetDefault("ldap_bindpw", *argServerLDAPBindPWPATH)
			c.LdapConf.BindPW = v.GetString("ldap_bindpw")

			v.SetDefault("ldap_filter", *argServerLDAPFilter)
			c.LdapConf.Filter = v.GetString("ldap_filter")

			v.SetDefault("ldap_result_attribute", *argServerLDAPResultAttr)
			c.LdapConf.SearchAttributes = []string{v.GetString("ldap_result_attribute")}

			v.SetDefault("ldap_starttls", *argServerLDAPStartTLS)
			c.LdapConf.StartTLS = v.GetBool("ldap_starttls")

			v.SetDefault("ldap_tls_skip_verify", *argServerLDAPTLSVerify)
			c.LdapConf.TLSSkipVerify = v.GetBool("ldap_tls_skip_verify")

			v.SetDefault("ldap_tls_cafile", *argServerLDAPTLSCAFile)
			c.LdapConf.TLSCAFile = v.GetString("ldap_tls_cafile")

			v.SetDefault("ldap_tls_client_cert", *argServerLDAPTLSClientCert)
			c.LdapConf.TLSClientCert = v.GetString("ldap_tls_client_cert")

			v.SetDefault("ldap_tls_client_key", *argServerLDAPTLSClientKey)
			c.LdapConf.TLSClientKey = v.GetString("ldap_tls_client_key")

			v.SetDefault("ldap_sasl_external", *argServerLDAPSASLExternal)
			c.LdapConf.SASLExternal = v.GetBool("ldap_sasl_external")

			// LDAP scope (special: string base/one/sub → int)
			v.SetDefault("ldap_scope", *argServerLDAPScope)

			switch v.GetString("ldap_scope") {
			case BASE:
				c.LdapConf.Scope = ldap.ScopeBaseObject
			case ONE:
				c.LdapConf.Scope = ldap.ScopeSingleLevel
			case SUB:
				c.LdapConf.Scope = ldap.ScopeWholeSubtree
			default:
				log.Fatalf("ldap-scope value '%s' must be one of: base, one, sub\n", v.GetString("ldap_scope"))
			}

			// Idle pool size (capped to pool size for CLI values; env vars are not capped).
			idleDefault := *argServerLDAPIdlePoolSize
			poolDefault := *argServerLDAPPoolSize

			v.SetDefault("ldap_idle_pool_size", idleDefault)
			v.SetDefault("ldap_pool_size", poolDefault)

			c.LdapConf.IdlePoolSize = v.GetInt("ldap_idle_pool_size")
			c.LdapConf.PoolSize = v.GetInt("ldap_pool_size")
		}

		// --- Actions ---
		v.SetDefault("run_actions", *argServerRunActions)
		c.RunActions = v.GetBool("run_actions")

		if c.RunActions {
			v.SetDefault("run_action_operator", *argServerRunActionOperator)
			c.RunActionOperator = v.GetBool("run_action_operator")

			if c.RunActionOperator {
				v.SetDefault("operator_to", *argServerOperatorTo)
				c.EmailOperatorTo = v.GetString("operator_to")

				v.SetDefault("operator_from", *argServerOperatorFrom)
				c.EmailOperatorFrom = v.GetString("operator_from")

				v.SetDefault("operator_subject", *argServerOperatorSubject)
				c.EmailOperatorSubject = v.GetString("operator_subject")

				v.SetDefault("operator_message_ct", *argServerOperatorMessageCT)
				c.EmailOperatorMessageCT = v.GetString("operator_message_ct")

				v.SetDefault("operator_message_path", *argServerOperatorMessagePath)
				c.EmailOperatorMessagePath = v.GetString("operator_message_path")
			}
		}

		// --- Mail server ---
		v.SetDefault("mail_server_address", *argServerMailServer)
		c.MailServer = v.GetString("mail_server_address")

		v.SetDefault("mail_helo", *argServerMailHelo)
		c.MailHelo = v.GetString("mail_helo")

		v.SetDefault("mail_server_port", *argServerMailPort)
		c.MailPort = v.GetInt("mail_server_port")

		v.SetDefault("mail_username", *argServerMailUsername)
		c.MailUsername = v.GetString("mail_username")

		v.SetDefault("mail_password", *argServerMailPasswordPath)
		c.MailPassword = v.GetString("mail_password")

		v.SetDefault("mail_ssl_on_connect", *argServerMailSSL)
		c.MailSSL = v.GetBool("mail_ssl_on_connect")

		c.CompilePolicyRuntime()
	}
}
