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
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	deferText  = "Service temporarily not available"
	rejectText = "Policy violation. Please contact your support"
)

const na = "N/A"

// TTLStringMap is a type alias for a map[string]int64. It represents a map
// where the keys are strings and the values are time-to-live (TTL) values
// in the form of int64. This type is commonly used in the context of caching
// or storing data with expiration times.
type TTLStringMap map[string]int64

// RedisHomeCountries represents a type used to store information about home IP addresses and their corresponding countries.
// The IPs field is a map of known home IP addresses, where the keys are the IP addresses and the values are the time-to-live (TTL) values.
// The Countries field is a map of known home country codes, where the keys are the country codes and the values are the TTL values.
type RedisHomeCountries struct {
	// IPs is a field of type TTLStringMap in the RedisHomeCountries struct. The Redis tag for this field is "ips".
	IPs TTLStringMap `redis:"ips"`

	// Countries represents a Time To Live (TTL) string map stored in Redis with the key name "countries".
	Countries TTLStringMap `redis:"countries"`
}

// PolicyResponse represents the response from the policy check.
type PolicyResponse struct {
	// `fired` is a boolean field in the `PolicyResponse` struct that indicates whether any policy has been triggered or not.
	fired bool

	// whitelisted represents a boolean field in the PolicyResponse struct indicating whether the remote client is whitelisted or not.
	whitelisted bool

	currentClientIP string

	currentCountryCode string

	// totalIPs represents the total number of IP addresses associated with a remote client.
	// It is an integer field in the PolicyResponse struct.
	totalIPs int

	// totalCountries is an integer field in the PolicyResponse struct. It represents the total number of countries associated with a remote client.
	totalCountries int

	// homeIPsSeen is a slice of strings representing the IP addresses belonging to the home network of a remote client.
	homeIPsSeen []string

	// foreignIPsSeen represents a slice of strings containing the foreign IP addresses seen by a remote client.
	foreignIPsSeen []string

	// homeCountriesSeen represents a slice of strings containing the country codes of home countries seen by a remote
	// client.
	homeCountriesSeen []string

	// foreignCountriesSeen represents a slice of strings containing the country codes of foreign countries seen by a
	// remote client.
	foreignCountriesSeen []string
}

// PolicyInput is the typed internal representation shared by HTTP and socket policy requests.
type PolicyInput struct {
	Sender   string
	ClientIP string
}

// NewPolicyInput validates sender and client IP values before they enter the policy hotpath.
func NewPolicyInput(sender, clientIP string) (PolicyInput, error) {
	input := PolicyInput{
		Sender:   sender,
		ClientIP: clientIP,
	}

	if err := input.Validate(); err != nil {
		return PolicyInput{}, err
	}

	return input, nil
}

// NewPolicyInputFromMap translates the Postfix-style policy request map into the typed policy input.
func NewPolicyInputFromMap(policyRequest map[string]string) (PolicyInput, error) {
	sender, clientIP, err := initializePolicy(policyRequest)
	if err != nil {
		return PolicyInput{}, err
	}

	return NewPolicyInput(sender, clientIP)
}

// Validate enforces the minimal policy input contract required by all policy evaluators.
func (p PolicyInput) Validate() error {
	if p.Sender == "" || p.ClientIP == "" {
		return errPolicyProtocol
	}

	return nil
}

// RemoteClient represents a remote client and its related information.
// It contains the following properties:
//   - ForeignIPs: A map of known IP addresses with their time-to-live (TTL) values.
//   - ForeignCountries: A map of known country codes with their TTL values.
//   - HomeCountries: A pointer to a RedisHomeCountries object that contains
//     information about home IP addresses and their corresponding countries.
//   - Actions: A slice of strings representing the actions that may have been executed.
//   - Locked: A boolean indicating if the account is permanently locked.
//
// Note that TTLStringMap is a type alias for map[string]int64, and RedisHomeCountries
// is a separate type defined in another package.
//
// The RemoteClient type provides several methods for manipulating and cleaning up
// the data in its properties, such as cleaning up expired country codes and IP addresses,
// adding country codes, and checking if certain properties exist or are empty.
//
// Example usage:
//
//	rc := &RemoteClient{
//	  ForeignIPs:           make(TTLStringMap),
//	  ForeignCountries:     make(TTLStringMap),
//	  HomeCountries: &RedisHomeCountries{ForeignIPs: make(TTLStringMap), ForeignCountries: make(TTLStringMap)},
//	  Actions:       []string{"action1", "action2"},
//	  Locked:        false,
//	}
//
// rc.AddForeignCountryCode("US")
// rc.CleanUpForeignCountries()
// rc.CleanUpHomeCountries()
// rc.CleanUpForeignIPs()
// rc.CleanUpHomeIPs()
// rc.haveForeignCountries()
// rc.haveForeignIPs()
// rc.haveHome()
// rc.haveHomeCountries()
// rc.haveHomeIPs()
type RemoteClient struct {
	// ForeignIPs represents  a Time To Live (TTL) string map with the Redis tag "ips".
	ForeignIPs TTLStringMap `redis:"ips"`

	// ForeignCountries represents a Time To Live (TTL) string map stored in Redis with the key name "countries".
	ForeignCountries TTLStringMap `redis:"countries"`

	// HomeCountries represents a field used to store RedisHomeCountries data in the Redis database.
	// It is tagged with "home_countries" for Redis mapping.
	HomeCountries *RedisHomeCountries `redis:"home_countries"`

	// Actions represents a list of strings. It is tagged with "redis:actions"
	// for mapping purposes in Redis.
	Actions []string `redis:"actions"`

	// Locked is a boolean field indicating whether a remote client account is locked
	Locked bool `redis:"locked"`
}

// haveHome checks if the RemoteClient has a non-nil HomeCountries map.
// It returns true if the HomeCountries map exists, otherwise it returns false.
func (r *RemoteClient) haveHome() bool {
	return r.HomeCountries != nil
}

// haveHomeCountries checks if the RemoteClient has a non-nil HomeCountries map and non-nil ForeignCountries map.
// It returns true if both maps exist and are not empty, otherwise it returns false.
func (r *RemoteClient) haveHomeCountries() bool {
	if r.haveHome() {
		return r.HomeCountries.Countries != nil
	}

	return false
}

// haveHomeIPs checks if the RemoteClient has a non-nil HomeCountries map and non-nil ForeignIPs map.
// It returns true if both maps exist and are not empty, otherwise it returns false.
func (r *RemoteClient) haveHomeIPs() bool {
	if r.haveHome() {
		return r.HomeCountries.IPs != nil
	}

	return false
}

// haveForeignCountries checks if the RemoteClient has a non-nil ForeignCountries map.
// It returns true if the ForeignCountries map exists and is not empty, otherwise it returns false.
func (r *RemoteClient) haveForeignCountries() bool {
	return r.ForeignCountries != nil
}

// haveForeignIPs checks if the RemoteClient has a non-nil ForeignIPs map.
// It returns true if the ForeignIPs map exists and is not empty, otherwise it returns false.
func (r *RemoteClient) haveForeignIPs() bool {
	return r.ForeignIPs != nil
}

// CleanUpForeignCountries removes expired country codes from the RemoteClient's ForeignCountries map.
// If the map does not exist or is empty, it does nothing.
// It iterates over the country codes in the map, and for each code, checks if its lifetime
// exceeds the configured Redis TTL. If it does, the code is removed from the map.
// The cleaning logic is based on the current timestamp and the created timestamp for each country code.
func (r *RemoteClient) CleanUpForeignCountries() {
	if !r.haveForeignCountries() {
		return
	}

	countryCodes := make(TTLStringMap)

	for country, created := range r.ForeignCountries {
		lifetime := time.Duration(config.RedisTTL) * time.Second

		if time.Now().UnixNano()-lifetime.Nanoseconds() < created {
			countryCodes[country] = created
		}
	}

	r.ForeignCountries = countryCodes
}

// CleanUpHomeCountries removes expired home country codes from the RemoteClient's HomeCountries map.
// If the HomeCountries map does not exist or is empty, it does nothing.
// It iterates over the country codes in the map, and for each code, checks if its lifetime
// exceeds the configured Redis TTL. If it does, the code is removed from the HomeCountries map.
// The cleaning logic is based on the current timestamp and the created timestamp for each country code.
// If the RemoteClient does not have a HomeCountries map, it creates an empty map.
func (r *RemoteClient) CleanUpHomeCountries() {
	if !r.haveHomeCountries() {
		return
	}

	countryCodes := make(TTLStringMap)

	for country, created := range r.HomeCountries.Countries {
		lifetime := time.Duration(config.RedisTTL) * time.Second

		if time.Now().UnixNano()-lifetime.Nanoseconds() < created {
			countryCodes[country] = created
		}
	}

	r.HomeCountries.Countries = countryCodes
}

// CleanUpForeignIPs removes expired IP addresses from the RemoteClient's ForeignIPs map.
// If the ForeignIPs map does not exist or is empty, it does nothing.
// It iterates over the IP addresses in the map, and for each address, checks if its lifetime
// exceeds the configured Redis TTL. If it does, the address is removed from the ForeignIPs map.
// The cleaning logic is based on the current timestamp and the created timestamp for each IP address.
// If the RemoteClient does not have an ForeignIPs map, it creates an empty map.
func (r *RemoteClient) CleanUpForeignIPs() {
	if !r.haveForeignIPs() {
		return
	}

	ips := make(TTLStringMap)

	for ipAddress, created := range r.ForeignIPs {
		lifetime := time.Duration(config.RedisTTL) * time.Second

		if time.Now().UnixNano()-lifetime.Nanoseconds() < created {
			ips[ipAddress] = created
		}
	}

	r.ForeignIPs = ips
}

// CleanUpHomeIPs removes expired home IP addresses from the RemoteClient's HomeCountries map.
// If the HomeCountries map does not exist or is empty, it does nothing.
// It iterates over the IP addresses in the map, and for each address, checks if its lifetime
// exceeds the configured Redis TTL. If it does, the address is removed from the HomeCountries map.
// The cleaning logic is based on the current timestamp and the created timestamp for each IP address.
// If the RemoteClient does not have a HomeCountries map, it creates an empty map.
func (r *RemoteClient) CleanUpHomeIPs() {
	if !r.haveHomeIPs() {
		return
	}

	ips := make(TTLStringMap)

	for ipAddress, created := range r.HomeCountries.IPs {
		lifetime := time.Duration(config.RedisTTL) * time.Second

		if time.Now().UnixNano()-lifetime.Nanoseconds() < created {
			ips[ipAddress] = created
		}
	}

	r.HomeCountries.IPs = ips
}

// AddForeignCountryCode adds a country code to the RemoteClient's ForeignCountries map.
// If the country code is empty, it does nothing.
// If the RemoteClient is not locked, it cleans up the ForeignCountries using the CleanUpForeignCountries method.
// If the ForeignCountries map does not exist, it creates one.
// Finally, it adds the country code with the current timestamp to the ForeignCountries map.
func (r *RemoteClient) AddForeignCountryCode(countryCode string) {
	if countryCode == "" {
		return
	}

	if !r.Locked {
		r.CleanUpForeignCountries()
	}

	if !r.haveForeignCountries() {
		r.ForeignCountries = make(TTLStringMap)
	}

	r.ForeignCountries[countryCode] = time.Now().UnixNano()
}

// AddHomeCountryCode adds a home country code to the RemoteClient's HomeCountries map.
// If the country code is empty, it does nothing.
// If the RemoteClient does not have a HomeCountries map, it creates one.
// If the RemoteClient is not locked, it cleans up the HomeCountries using the CleanUpHomeCountries method.
// If the HomeCountries map does not exist, it creates one.
// Finally, it adds the country code with the current timestamp to the HomeCountries' ForeignCountries map.
func (r *RemoteClient) AddHomeCountryCode(countryCode string) {
	if countryCode == "" {
		return
	}

	if !r.haveHome() {
		r.HomeCountries = &RedisHomeCountries{}
	}

	if !r.Locked {
		r.CleanUpHomeCountries()
	}

	if !r.haveHomeCountries() {
		r.HomeCountries.Countries = make(TTLStringMap)
	}

	r.HomeCountries.Countries[countryCode] = time.Now().UnixNano()
}

// AddForeignIPAddress adds an IP address to the RemoteClient's ForeignIPs map.
// If the RemoteClient is not locked, it cleans up the ForeignIPs using the CleanUpForeignIPs method.
// If the ForeignIPs map does not exist, it creates one.
// Finally, it adds the ipAddress with the current timestamp to the ForeignIPs map.
func (r *RemoteClient) AddForeignIPAddress(ipAddress string) {
	if !r.Locked {
		r.CleanUpForeignIPs()
	}

	if !r.haveForeignIPs() {
		r.ForeignIPs = make(TTLStringMap)
	}

	r.ForeignIPs[ipAddress] = time.Now().UnixNano()
}

// AddHomeIPAddress adds a home IP address to the RemoteClient's HomeCountries map.
// If the RemoteClient does not have a HomeCountries map, it creates one.
// If the RemoteClient is not locked, it cleans up the HomeIPs using the CleanUpHomeIPs method.
// If the HomeCountries map does not exist, it creates one.
// Finally, it adds the ipAddress with the current timestamp to the HomeCountries' ForeignIPs map.
func (r *RemoteClient) AddHomeIPAddress(ipAddress string) {
	if !r.haveHome() {
		r.HomeCountries = &RedisHomeCountries{}
	}

	if !r.Locked {
		r.CleanUpHomeIPs()
	}

	if !r.haveHomeIPs() {
		r.HomeCountries.IPs = make(TTLStringMap)
	}

	r.HomeCountries.IPs[ipAddress] = time.Now().UnixNano()
}

// date2String converts a Unix timestamp to a string representation of the corresponding date and time.
// It takes an int64 argument representing the Unix timestamp and returns a string.
// The function uses the time package to perform the conversion.
// The returned string is in the format "2006-01-02 15:04:05.999999999 -0700 MST",
// where the numbers represent the year, month, day, hour, minute, second, and nanosecond respectively,
// and the other parts represent the time zone information.
// The function assumes that the input timestamp is in nanoseconds.
func date2String(date int64) string {
	unixtime := time.Unix(0, date)

	return time.Date(
		unixtime.Year(),
		unixtime.Month(),
		unixtime.Day(),
		unixtime.Hour(),
		unixtime.Minute(),
		unixtime.Second(),
		unixtime.Nanosecond(),
		time.Local,
	).String()
}

// isDebugLoggingEnabled avoids preparing expensive debug log values when debug output is disabled.
func isDebugLoggingEnabled() bool {
	return config != nil && config.VerboseLevel >= logLevelDebug
}

// isInfoLoggingEnabled avoids preparing expensive info log values when info output is disabled.
func isInfoLoggingEnabled() bool {
	return config != nil && config.VerboseLevel >= logLevelInfo
}

// initializePolicy initializes the sender and clientIP variables by extracting the values from the
// policyRequest map. It checks if the request is "smtpd_access_policy" and returns an error
// if it's not. It determines the user attribute to use based on the configuration and checks if
// the sender and clientIP are present in the policyRequest map. If any of them is missing or
// empty, it returns an error. Finally, it returns the sender, clientIP, and nil error.
func initializePolicy(policyRequest map[string]string) (string, string, error) {
	request, found := policyRequest[PolicyRequest]
	if !found || request != PolicyProtocolSMTPD {
		return "", "", errPolicyProtocol
	}

	userAttr := Sender
	if config.UseSASLUsername {
		userAttr = SASLUsername
	}

	sender, found := policyRequest[userAttr]
	if !found || len(sender) == 0 {
		return "", "", errPolicyProtocol
	}

	clientIP, found := policyRequest[ClientAddress]
	if !found || len(clientIP) == 0 {
		return "", "", errPolicyProtocol
	}

	return sender, clientIP, nil
}

// checkUserInLDAPContext checks LDAP user state while preserving trace context for the request.
func checkUserInLDAPContext(ctx context.Context, sender, guid string) (bool, error) {
	if !config.UseLDAP {
		return false, nil
	}

	start := time.Now()
	result := resultUnknown

	obs := currentObservability()
	if obs != nil {
		var span trace.Span

		ctx, span = obs.StartSpan(ctx, "ldap.user_check", attribute.String("ldap.operation", "user_check"))
		defer span.End()
		defer func() {
			obs.ObserveLDAPOperation(ctx, "user_check", result, time.Since(start))
		}()
	}

	ldapReplyChan := make(chan *LdapReply)
	ldapRequest := &LdapRequest{
		ctx:       ctx,
		username:  sender,
		guid:      &guid,
		replyChan: ldapReplyChan,
	}

	ldapRequestChan <- ldapRequest

	ldapReply := <-ldapReplyChan

	if ldapReply.err != nil {
		return handleLDAPUserCheckError(ctx, obs, ldapReply.err, sender, guid, &result)
	}

	if _, mapKeyFound := ldapReply.result[config.SearchAttributes[ldapSingleValue]]; mapKeyFound {
		result = resultFound

		_ = level.Debug(logger).Log("guid", guid, "msg", fmt.Sprintf("User '%s' found in LDAP", sender))

		return true, nil
	}

	result = resultNotFound

	return false, nil
}

// handleLDAPUserCheckError maps LDAP lookup errors to user-known policy semantics.
func handleLDAPUserCheckError(ctx context.Context, obs *Observability, err error, sender, guid string, result *string) (bool, error) {
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) && ldapError.ResultCode == uint16(ldap.LDAPResultNoSuchObject) {
		*result = resultNotFound
		_ = level.Info(logger).Log("guid", guid, "msg", fmt.Sprintf("User '%s' does not exist", sender))

		return false, nil
	}

	*result = resultError

	if obs != nil {
		obs.RecordSpanError(trace.SpanFromContext(ctx), err)
	}

	_ = level.Error(logger).Log("guid", guid, "error", err.Error())

	return true, err
}

// checkUserInCDBContext checks CDB user state while preserving trace context for the request.
func checkUserInCDBContext(ctx context.Context, sender string, guid string) (bool, error) {
	if !config.UseCDB {
		return false, nil
	}

	start := time.Now()
	result := resultNotFound

	obs := currentObservability()
	if obs != nil {
		var span trace.Span

		ctx, span = obs.StartSpan(ctx, "cdb.lookup", attribute.String("cdb.operation", "get"))
		defer span.End()
		defer func() {
			obs.ObserveCDBLookup(ctx, result, time.Since(start))
		}()
	}

	if db := cdbStore.Load().(*cdb.CDB); db != nil {
		value, err := db.Get([]byte(sender))
		if err != nil {
			result = resultError

			if obs != nil {
				obs.RecordSpanError(trace.SpanFromContext(ctx), err)
			}

			return false, err
		}

		if value != nil {
			result = resultFound

			_ = level.Debug(logger).Log("guid", guid, "msg", fmt.Sprintf("User '%s' found in CDB", sender))

			return true, nil
		}
	}

	return false, nil
}

// fetchRemoteClientContext loads the cached policy state with the request context.
func fetchRemoteClientContext(ctx context.Context, sender string) (*RemoteClient, error) {
	key := fmt.Sprintf("%s%s", config.RedisPrefix, sender)
	remoteClient := &RemoteClient{}

	redisValue, err := redisHandleReplica.Get(ctx, key).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	if redisValue != nil {
		if err := json.Unmarshal(redisValue, remoteClient); err != nil {
			return nil, err
		}
	}

	return remoteClient, nil
}

// logClientDetails logs the client details, including IP addresses and timestamps,
// if the remote client has IP addresses and/or home IP addresses.
// The log messages are recorded at the debug level using the logger.
// The log messages include the client GUID, IP address or home IP address, and the timestamp.
// The function takes a pointer to a RemoteClient struct and a GUID string as parameters.
// If the remote client has IP addresses, the function iterates over each IP address
// and logs the GUID, IP address, and timestamp.
// If the remote client has home IP addresses, the function iterates over each home IP address
// and logs the GUID, home IP address, and timestamp.
// The function does not return any values.
func logClientDetails(remoteClient *RemoteClient, guid string) {
	if !isDebugLoggingEnabled() {
		return
	}

	if remoteClient.haveForeignIPs() {
		for ipAddress, date := range remoteClient.ForeignIPs {
			_ = level.Debug(logger).Log("guid", guid, "ip_address", ipAddress, "timestamp", date2String(date))
		}
	}

	if remoteClient.haveHomeIPs() {
		for ipAddress, date := range remoteClient.HomeCountries.IPs {
			_ = level.Debug(logger).Log("guid", guid, "home_ip_address", ipAddress, "timestamp", date2String(date))
		}
	}
}

// logCountryDetails logs the country details for a remote client.
// If the country code is not present, it logs a debug message with the client IP.
// If the remote client has countries, it logs the country codes and timestamps.
// If the remote client has home countries, it logs the home country codes and timestamps.
func logCountryDetails(remoteClient *RemoteClient, countryCode, clientIP, guid string) {
	if !isDebugLoggingEnabled() {
		return
	}

	if countryCode == "" {
		_ = level.Debug(logger).Log("guid", guid, "msg", "No country code present", "client_address", clientIP)
	} else {
		if remoteClient.haveForeignCountries() {
			for country, date := range remoteClient.ForeignCountries {
				_ = level.Debug(logger).Log("guid", guid, "country_code", country, "timestamp", date2String(date))
			}
		}

		if remoteClient.haveHomeCountries() {
			for country, date := range remoteClient.HomeCountries.Countries {
				_ = level.Debug(logger).Log("guid", guid, "home_country_code", country, "timestamp", date2String(date))
			}
		}
	}
}

// applyCustomSettings applies custom settings based on the sender from the given custom settings.
// The allowedMaxForeignIPs, allowedMaxForeignCountries, trustedIPs, trustedCountries, homeCountries, allowedMaxHomeIPs,
// and allowedMaxHomeCountries variables are updated with the corresponding values from the custom settings.
func applyCustomSettings(customSettings *CustomSettings, sender string, allowedMaxForeignIPs, allowedMaxForeignCountries *int, trustedIPs, trustedCountries *[]string, homeCountries *[]string, allowedMaxHomeIPs, allowedMaxHomeCountries *int) {
	setting := findCustomSetting(customSettings, sender)
	if setting == nil {
		return
	}

	if setting.IPs > 0 {
		*allowedMaxForeignIPs = setting.IPs
	}

	if setting.Countries > 0 {
		*allowedMaxForeignCountries = setting.Countries
	}

	if len(setting.TrustedIPs) > 0 {
		*trustedIPs = setting.TrustedIPs
	}

	if len(setting.TrustedCountries) > 0 {
		*trustedCountries = setting.TrustedCountries
	}

	applyCustomHomeSettings(setting, homeCountries, allowedMaxHomeIPs, allowedMaxHomeCountries)
}

// findCustomSetting returns the sender-specific custom settings entry.
func findCustomSetting(customSettings *CustomSettings, sender string) *Account {
	if customSettings == nil {
		return nil
	}

	for index := range customSettings.Data {
		if customSettings.Data[index].Sender == sender {
			return &customSettings.Data[index]
		}
	}

	return nil
}

// applyCustomHomeSettings applies sender-specific home country overrides.
func applyCustomHomeSettings(setting *Account, homeCountries *[]string, allowedMaxHomeIPs, allowedMaxHomeCountries *int) {
	if setting.HomeCountries == nil || len(setting.Codes) == 0 {
		return
	}

	*homeCountries = setting.Codes

	if setting.HomeCountries.IPs > 0 {
		*allowedMaxHomeIPs = setting.HomeCountries.IPs
	}

	if setting.HomeCountries.Countries > 0 {
		*allowedMaxHomeCountries = setting.HomeCountries.Countries
	}
}

// checkCountryPolicy keeps the legacy helper API and evaluates country rules through request-local policy settings.
func checkCountryPolicy(remoteClient *RemoteClient, trustedCountries []string, countryCode string, policyResponse *PolicyResponse, allowedMaxForeignCountries, allowedMaxHomeCountries int, guid string, isHome bool) bool {
	settings := NewPolicySettings(nil, trustedCountries, nil, 0, 0, allowedMaxForeignCountries, allowedMaxHomeCountries)

	return settings.CheckCountryPolicy(remoteClient, countryCode, policyResponse, guid, isHome)
}

// checkIPsPolicy keeps the legacy helper API and evaluates IP rules through request-local policy settings.
func checkIPsPolicy(remoteClient *RemoteClient, trustedIPs []string, clientIP string, policyResponse *PolicyResponse, allowedMaxForeignIPs, allowedMaxHomeIPs int, guid string, isHome bool) bool {
	settings := NewPolicySettings(trustedIPs, nil, nil, allowedMaxForeignIPs, allowedMaxHomeIPs, 0, 0)

	return settings.CheckIPPolicy(remoteClient, clientIP, policyResponse, guid, isHome)
}

// isTrustedIP keeps the legacy helper API and checks an IP address through a compiled matcher.
func isTrustedIP(trustedIPs []string, clientIP string, guid string) bool {
	return NewNetworkMatcher(trustedIPs).ContainsString(clientIP, guid)
}

// networkContainsIP checks if the provided IP address is within the trusted network range.
// It parses the trusted IP or network string and verifies if the IP address is contained in the network.
// If the trusted IP or network cannot be parsed, it logs an error and returns false.
// It logs the IP address and the trusted network being checked.
// If the IP address is found within the trusted network, it logs a success message and returns true.
// Otherwise, it returns false.
func networkContainsIP(trustedIPOrNet string, ipAddress net.IP, guid string) bool {
	_, network, err := net.ParseCIDR(trustedIPOrNet)
	if err != nil {
		_ = level.Error(logger).Log("guid", guid, "msg", "Not a trusted network", "network", trustedIPOrNet, "error", err.Error())

		return false
	}

	if isDebugLoggingEnabled() {
		_ = level.Debug(logger).Log("guid", guid, "msg", "Checking", "ip_address", ipAddress.String(), "trusted_network", network.String())
	}

	if network.Contains(ipAddress) {
		if isDebugLoggingEnabled() {
			_ = level.Debug(logger).Log("guid", guid, "msg", "IP matched", "ip_address", ipAddress.String())
		}

		return true
	}

	return false
}

// checkUserKnownContext checks all configured user directories with request context propagation.
func checkUserKnownContext(ctx context.Context, sender, guid string) (bool, error) {
	if config.ForceUserKnown {
		return true, nil
	}

	userKnown, err := checkUserInLDAPContext(ctx, sender, guid)
	if err != nil {
		return false, err
	}

	if !userKnown {
		userKnown, err = checkUserInCDBContext(ctx, sender, guid)
		if err != nil {
			return false, err
		}
	}

	return userKnown, nil
}

// fetchAndLogRemoteClientContext fetches cached state with request context propagation.
func fetchAndLogRemoteClientContext(ctx context.Context, sender, clientIP, countryCode, guid string) (*RemoteClient, error) {
	remoteClient, err := fetchRemoteClientContext(ctx, sender)
	if err != nil {
		return nil, err
	}

	logClientDetails(remoteClient, guid)
	logCountryDetails(remoteClient, countryCode, clientIP, guid)

	return remoteClient, nil
}

// handleClientActionsContext runs side-effect actions with request context propagation.
func handleClientActionsContext(ctx context.Context, remoteClient *RemoteClient, sender string, userKnown bool, guid string, requireActions bool) {
	if config.RunActions && requireActions {
		err := runOperatorActionContext(ctx, remoteClient, sender, userKnown, guid)
		if err != nil {
			_ = level.Error(logger).Log("guid", guid, "error", err.Error())
		}
	}
}

// runOperatorActionContext processes the operator action with metrics and tracing.
func runOperatorActionContext(ctx context.Context, remoteClient *RemoteClient, sender string, userKnown bool, guid string) error {
	if userKnown && config.RunActionOperator && shouldRunOperator(remoteClient) {
		action := &EmailOperator{}
		start := time.Now()
		result := resultOK

		obs := currentObservability()
		if obs != nil {
			var span trace.Span

			ctx, span = obs.StartSpan(ctx, "action.operator", attribute.String("action.name", "operator"))
			defer span.End()
			defer func() {
				obs.ObserveAction(ctx, "operator", result, time.Since(start))
			}()
		}

		if err := action.Call(sender); err != nil {
			result = resultError

			if obs != nil {
				obs.RecordSpanError(trace.SpanFromContext(ctx), err)
			}

			return err
		}

		_ = level.Debug(logger).Log("guid", guid, "msg", "Action 'operator' finished successfully")

		remoteClient.Actions = append(remoteClient.Actions, "operator")
	}

	return nil
}

// shouldRunOperator determines whether the "operator" action should be run for the given remote client.
// It checks if the "operator" action already exists in the actions list of the remote client.
// If it does, it returns false to indicate that the action should not be run.
// If it doesn't, it returns true to indicate that the action should be run.
func shouldRunOperator(remoteClient *RemoteClient) bool {
	return !slices.Contains(remoteClient.Actions, "operator")
}

// redisCacheWritePlan describes the minimal Redis commands needed after the JSON value is written.
type redisCacheWritePlan struct {
	expiration        time.Duration
	deleteImmediately bool
}

// newRedisCacheWritePlan translates lock and TTL state into the Redis SET expiration strategy.
func newRedisCacheWritePlan(config *CmdLineConfig, remoteClient *RemoteClient) redisCacheWritePlan {
	if remoteClient.Locked {
		return redisCacheWritePlan{}
	}

	if config.RedisTTL <= 0 {
		return redisCacheWritePlan{deleteImmediately: true}
	}

	return redisCacheWritePlan{expiration: time.Duration(config.RedisTTL) * time.Second}
}

// updateRedisCacheContext stores policy state in Redis with request context propagation.
func updateRedisCacheContext(ctx context.Context, sender string, remoteClient *RemoteClient) error {
	redisValue, err := json.Marshal(remoteClient)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s%s", config.RedisPrefix, sender)
	writePlan := newRedisCacheWritePlan(config, remoteClient)

	if err = redisHandle.Set(ctx, key, redisValue, writePlan.expiration).Err(); err != nil {
		return err
	}

	if writePlan.deleteImmediately {
		return redisHandle.Expire(ctx, key, 0).Err()
	}

	return nil
}

// logPolicyResult logs the policy result using the provided policy response, remote client, sender,
// trusted countries, trusted ForeignIPs, and GUID. It uses the level.Info function from the logger
// to log the information with the following fields: guid, user attribute,
// foreign countries seen, home countries seen, home countries defined, trusted countries defined,
// total countries, allowed max foreign countries, allowed max home countries, foreign ForeignIPs seen,
// home ForeignIPs seen, trusted ForeignIPs defined, total ForeignIPs, allowed max foreign ForeignIPs, allowed max home ForeignIPs,
// and action status.
func logPolicyResult(policyResponse *PolicyResponse, remoteClient *RemoteClient, sender string, trustedCountries, trustedIPs []string, allowedMaxForeignIPs, allowedMaxHomeIPs, allowedMaxForeignCountries, allowedMaxHomeCountries int, guid string) {
	if !isInfoLoggingEnabled() {
		return
	}

	_ = level.Info(logger).Log("guid", guid,
		getUserAttribute(), sender,
		"current_client_ip", policyResponse.currentClientIP,
		"current_country_code", policyResponse.currentCountryCode,
		"foreign_countries_seen", getForeignCountriesSeen(remoteClient),
		"home_countries_seen", getHomeCountriesSeen(remoteClient),
		"home_countries_defined", getHouseCountries(),
		"trusted_countries_defined", getTrustedCountries(trustedCountries),
		"total_countries", getTotalCountries(remoteClient, policyResponse),
		"allowed_max_foreign_countries", allowedMaxForeignCountries,
		"allowed_max_home_countries", allowedMaxHomeCountries,
		"foreign_ips_seen", getForeignIPsSeen(remoteClient),
		"home_ips_seen", getHomeIPsSeen(remoteClient),
		"trusted_ips_defined", getTrustedIPs(trustedIPs),
		"total_ips", getTotalIPs(remoteClient, policyResponse),
		"allowed_max_foreign_ips", allowedMaxForeignIPs,
		"allowed_max_home_ips", allowedMaxHomeIPs,
		"action", getActionStatus(policyResponse),
	)
}

// updatePolicyResponse updates the fields of the PolicyResponse struct based on information from the RemoteClient.
// It populates the foreignIPsSeen, foreignCountriesSeen, homeIPsSeen, homeCountriesSeen, totalIPs, and totalCountries fields.
// The response parameter is a pointer to the PolicyResponse struct that needs to be updated.
// The client parameter is a pointer to the RemoteClient struct from which the information is extracted.
func updatePolicyResponse(response *PolicyResponse, client *RemoteClient) {
	response.foreignIPsSeen = strings.Split(getForeignIPsSeen(client), ",")
	response.foreignCountriesSeen = strings.Split(getForeignCountriesSeen(client), ",")
	response.homeIPsSeen = strings.Split(getHomeIPsSeen(client), ",")
	response.homeCountriesSeen = strings.Split(getHomeCountriesSeen(client), ",")
	response.totalIPs = getTotalIPs(client, response)
	response.totalCountries = getTotalCountries(client, response)
}

// getUserAttribute returns the attribute to be used for the user.
// If the global configuration flag UseSASLUsername is set to true, it
// returns the value of the constant SASLUsername. Otherwise, it returns
// the value of the constant Sender.
//
// Returns:
// - string: The user attribute.
func getUserAttribute() string {
	if config.UseSASLUsername {
		return SASLUsername
	}

	return Sender
}

// getForeignCountriesSeen returns a string containing all the foreign country codes seen by the remote client.
// If the remote client does not have any foreign country codes, it returns "N/A".
func getForeignCountriesSeen(remoteClient *RemoteClient) string {
	if remoteClient.haveForeignCountries() {
		var countries []string

		for country := range remoteClient.ForeignCountries {
			countries = append(countries, country)
		}

		return strings.Join(countries, ",")
	}

	return na
}

// getHomeCountriesSeen returns a string containing a comma-separated list of home countries
// seen by the provided remote client. If no home countries are found, it returns "N/A".
func getHomeCountriesSeen(remoteClient *RemoteClient) string {
	if remoteClient.haveHomeCountries() {
		var countries []string

		for country := range remoteClient.HomeCountries.Countries {
			countries = append(countries, country)
		}

		return strings.Join(countries, ",")
	}

	return na
}

// getHouseCountries returns a string containing all the home countries seen by the remote client.
// This function checks if the remote client has home countries and joins them with a comma.
// If there are no home countries available, it returns "N/A".
func getHouseCountries() string {
	if len(config.HomeCountries) > 0 {
		return strings.Join(config.HomeCountries, ",")
	}

	return na
}

// getTrustedCountries returns a string containing all the trusted countries. It takes in
// a slice of strings representing the trusted countries and joins them with a comma.
// If the slice is empty, it returns "N/A".
func getTrustedCountries(trustedCountries []string) string {
	if len(trustedCountries) > 0 {
		return strings.Join(trustedCountries, ",")
	}

	return na
}

// getTotalCountries returns the total number of countries based on the data provided by the remote client and policy response.
// It calculates the sum by checking if the remote client has countries and home countries, and adds their lengths if available.
// The final sum is assigned to the policy response's totalCountries property. The function returns the sum as an integer.
func getTotalCountries(remoteClient *RemoteClient, policyResponse *PolicyResponse) int {
	sum := 0

	if remoteClient.haveForeignCountries() {
		sum = len(remoteClient.ForeignCountries)
	}

	if remoteClient.haveHomeCountries() {
		sum += len(remoteClient.HomeCountries.Countries)
	}

	policyResponse.totalCountries = sum

	return sum
}

// getForeignIPsSeen returns a string containing all the foreign IP addresses
// seen by the remote client. If there are no IP addresses available, it returns "N/A".
func getForeignIPsSeen(remoteClient *RemoteClient) string {
	if remoteClient.haveForeignIPs() {
		var ips []string
		for ip := range remoteClient.ForeignIPs {
			ips = append(ips, ip)
		}

		return strings.Join(ips, ",")
	}

	return na
}

// getHomeIPsSeen returns a string containing a comma-separated list of all
// the home IP addresses seen by the given remote client. If the remote
// client does not have any home IP addresses, it returns "N/A".
func getHomeIPsSeen(remoteClient *RemoteClient) string {
	if remoteClient.haveHomeIPs() {
		var ips []string
		for ip := range remoteClient.HomeCountries.IPs {
			ips = append(ips, ip)
		}

		return strings.Join(ips, ",")
	}

	return na
}

// getTrustedIPs takes a slice of trustedIPs and returns a string representation
// of the trusted ForeignIPs separated by commas. If the trustedIPs slice is empty,
// the function returns "N/A".
func getTrustedIPs(trustedIPs []string) string {
	if len(trustedIPs) > 0 {
		return strings.Join(trustedIPs, ",")
	}

	return na
}

// getTotalIPs calculates the total number of IP addresses associated with a remote client.
// It takes a pointer to a RemoteClient and a pointer to a PolicyResponse as parameters.
// The function checks if the remote client has any IP addresses and adds them to the sum.
// If the remote client has home IP addresses, it also adds them to the sum.
// The total number of IP addresses is then assigned to the totalIPs field of the PolicyResponse.
// The function returns the sum of the IP addresses.
func getTotalIPs(remoteClient *RemoteClient, policyResponse *PolicyResponse) int {
	sum := 0

	if remoteClient.haveForeignIPs() {
		sum = len(remoteClient.ForeignIPs)
	}

	if remoteClient.haveHomeIPs() {
		sum += len(remoteClient.HomeCountries.IPs)
	}

	policyResponse.totalIPs = sum

	return sum
}

// getActionStatus returns the action status based on the given policy response.
// If the policy response indicates a policy violation (fired is true), it returns
// the rejectText constant. Otherwise, it returns "ok".
func getActionStatus(policyResponse *PolicyResponse) string {
	if policyResponse.fired {
		return rejectText
	}

	return resultOK
}

// setCurrentClientInfo sets the current client IP and country code in the PolicyResponse object.
// It takes the IP address, country code, and a pointer to the PolicyResponse object as input parameters.
// It assigns the IP address to the `currentClientIP` field and the country code to the `currentCountryCode` field
// of the PolicyResponse object.
func setCurrentClientInfo(ip string, code string, policyResponse *PolicyResponse) {
	policyResponse.currentClientIP = ip
	policyResponse.currentCountryCode = code
}

// getObservedPolicyResponse records source-level policy request metrics around the map-based API.
func getObservedPolicyResponse(ctx context.Context, source string, policyRequest map[string]string, guid string, info bool) (policyResponse *PolicyResponse, err error) {
	policyInput, err := NewPolicyInputFromMap(policyRequest)
	if err != nil {
		if obs := currentObservability(); obs != nil {
			obs.ObservePolicyRequest(ctx, source, resultError, 0)
		}

		return nil, err
	}

	return getObservedPolicyResponseFor(ctx, source, policyInput, guid, info)
}

// isIgnoredPolicyInput marks whitelisted requests and logs the matched ignore-network entry when info logging is active.
func isIgnoredPolicyInput(clientIP, guid string, policyResponse *PolicyResponse) bool {
	ignoreNet, found := config.IgnoreNetworkMatcher().MatchString(clientIP, guid)
	if !found {
		return false
	}

	policyResponse.whitelisted = true

	if isInfoLoggingEnabled() {
		_ = level.Info(logger).Log(
			"guid", guid,
			"msg", "IP address found in ignore-networks",
			"client_address", clientIP,
			"ignore_networks", ignoreNet,
		)
	}

	return true
}

// effectivePolicySettings returns request-local policy settings with sender-specific custom overrides applied.
func effectivePolicySettings(sender string) *PolicySettings {
	policySettings := config.PolicySettings()

	if customSettings := loadCustomSettings(); customSettings != nil {
		customSettings.ApplyTo(sender, policySettings)
	}

	return policySettings
}

// fetchPolicySubjectContext loads user-known state and current Redis policy state with request context propagation.
func fetchPolicySubjectContext(ctx context.Context, sender, clientIP, countryCode, guid string) (bool, *RemoteClient, bool, error) {
	userKnown, err := checkUserKnownContext(ctx, sender, guid)
	if err != nil {
		return false, nil, true, err
	}

	remoteClient, err := fetchAndLogRemoteClientContext(ctx, sender, clientIP, countryCode, guid)
	if err != nil {
		return false, nil, false, err
	}

	return userKnown, remoteClient, false, nil
}

// finalizePolicyDecisionContext runs side effects and response enrichment with request context propagation.
func finalizePolicyDecisionContext(ctx context.Context, sender string, remoteClient *RemoteClient, policyResponse *PolicyResponse, userKnown, requireActions bool, guid string) error {
	if remoteClient.Locked {
		policyResponse.fired = true
		requireActions = true
	}

	handleClientActionsContext(ctx, remoteClient, sender, userKnown, guid, requireActions)

	if err := updateRedisCacheContext(ctx, sender, remoteClient); err != nil {
		return err
	}

	updatePolicyResponse(policyResponse, remoteClient)

	return nil
}

// getPolicyResponseFor evaluates a typed policy request and generates a structured policy response object.
// It initializes the request, validates input, handles ignored networks, evaluates user information,
// processes client data, and applies custom settings to determine policy actions.
// Returns a pointer to PolicyResponse and an error if any issue occurs during processing.
// If info is true, it only determines the country code and returns early with just the necessary data.
// getObservedPolicyResponseFor records source-level policy request metrics around the typed API.
func getObservedPolicyResponseFor(ctx context.Context, source string, policyInput PolicyInput, guid string, info bool) (policyResponse *PolicyResponse, err error) {
	start := time.Now()

	obs := currentObservability()
	if obs != nil {
		var span trace.Span

		ctx, span = obs.StartSpan(ctx,
			"policy.request",
			attribute.String("policy.source", source),
			attribute.Bool("policy.info_only", info),
		)
		defer span.End()
	}

	policyResponse, err = getPolicyResponseForContext(ctx, policyInput, guid, info)
	outcome := policyOutcome(policyResponse, err, info)

	if obs != nil {
		obs.ObservePolicyRequest(ctx, source, outcome, time.Since(start))

		if err != nil {
			obs.RecordSpanError(trace.SpanFromContext(ctx), err)
		}
	}

	return policyResponse, err
}

// policyOutcome normalizes a policy response into low-cardinality metric labels.
func policyOutcome(policyResponse *PolicyResponse, err error, info bool) string {
	if err != nil {
		return resultError
	}

	if policyResponse == nil {
		return resultEmpty
	}

	if policyResponse.whitelisted {
		return resultWhitelist
	}

	if info {
		return resultInfo
	}

	if policyResponse.fired {
		return resultReject
	}

	return resultAccept
}

// getPolicyResponseForContext evaluates a typed policy request with request context propagation.
func getPolicyResponseForContext(ctx context.Context, policyInput PolicyInput, guid string, info bool) (policyResponse *PolicyResponse, err error) {
	policyResponse = &PolicyResponse{}

	if err = policyInput.Validate(); err != nil {
		return nil, err
	}

	sender := policyInput.Sender
	clientIP := policyInput.ClientIP

	if isIgnoredPolicyInput(clientIP, guid, policyResponse) {
		return
	}

	countryCode := getCountryCodeWithContext(ctx, clientIP)

	setCurrentClientInfo(clientIP, countryCode, policyResponse)

	// If info flag is true, return early with just the country code information
	if info {
		return policyResponse, nil
	}

	userKnown, remoteClient, keepResponseOnError, err := fetchPolicySubjectContext(ctx, sender, clientIP, countryCode, guid)
	if err != nil {
		if keepResponseOnError {
			return policyResponse, err
		}

		return nil, err
	}

	policySettings := effectivePolicySettings(sender)
	requireActions := policySettings.Evaluate(remoteClient, countryCode, policyResponse, clientIP, guid)

	if err = finalizePolicyDecisionContext(ctx, sender, remoteClient, policyResponse, userKnown, requireActions, guid); err != nil {
		return nil, err
	}

	logPolicyResult(
		policyResponse,
		remoteClient,
		sender,
		policySettings.TrustedCountries,
		policySettings.TrustedIPs,
		policySettings.AllowedMaxForeignIPs,
		policySettings.AllowedMaxHomeIPs,
		policySettings.AllowedMaxForeignCountries,
		policySettings.AllowedMaxHomeCountries,
		guid,
	)

	return policyResponse, nil
}
