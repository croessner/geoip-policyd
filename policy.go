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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
	"github.com/redis/go-redis/v9"
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

// RemoteClient represents a remote client and its related information.
// It contains the following properties:
//   - IPs: A map of known IP addresses with their time-to-live (TTL) values.
//   - Countries: A map of known country codes with their TTL values.
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
//	  IPs:           make(TTLStringMap),
//	  Countries:     make(TTLStringMap),
//	  HomeCountries: &RedisHomeCountries{IPs: make(TTLStringMap), Countries: make(TTLStringMap)},
//	  Actions:       []string{"action1", "action2"},
//	  Locked:        false,
//	}
//
// rc.AddCountryCode("US")
// rc.CleanUpCountries()
// rc.CleanUpHomeCountries()
// rc.CleanUpIPs()
// rc.CleanUpHomeIPs()
// rc.haveCountries()
// rc.haveIPs()
// rc.haveHome()
// rc.haveHomeCountries()
// rc.haveHomeIPs()
type RemoteClient struct {
	// IPs represents  a Time To Live (TTL) string map with the Redis tag "ips".
	IPs TTLStringMap `redis:"ips"`

	// Countries represents a Time To Live (TTL) string map stored in Redis with the key name "countries".
	Countries TTLStringMap `redis:"countries"`

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

// haveHomeCountries checks if the RemoteClient has a non-nil HomeCountries map and non-nil Countries map.
// It returns true if both maps exist and are not empty, otherwise it returns false.
func (r *RemoteClient) haveHomeCountries() bool {
	if r.haveHome() {
		return r.HomeCountries.Countries != nil
	}

	return false
}

// haveHomeIPs checks if the RemoteClient has a non-nil HomeCountries map and non-nil IPs map.
// It returns true if both maps exist and are not empty, otherwise it returns false.
func (r *RemoteClient) haveHomeIPs() bool {
	if r.haveHome() {
		return r.HomeCountries.IPs != nil
	}

	return false
}

// haveCountries checks if the RemoteClient has a non-nil Countries map.
// It returns true if the Countries map exists and is not empty, otherwise it returns false.
func (r *RemoteClient) haveCountries() bool {
	return r.Countries != nil
}

// haveIPs checks if the RemoteClient has a non-nil IPs map.
// It returns true if the IPs map exists and is not empty, otherwise it returns false.
func (r *RemoteClient) haveIPs() bool {
	return r.IPs != nil
}

// CleanUpCountries removes expired country codes from the RemoteClient's Countries map.
// If the map does not exist or is empty, it does nothing.
// It iterates over the country codes in the map, and for each code, checks if its lifetime
// exceeds the configured Redis TTL. If it does, the code is removed from the map.
// The cleaning logic is based on the current timestamp and the created timestamp for each country code.
func (r *RemoteClient) CleanUpCountries() {
	if !r.haveCountries() {
		return
	}

	countryCodes := make(TTLStringMap)

	for country, created := range r.Countries {
		lifetime := time.Duration(config.RedisTTL) * time.Second

		if time.Now().UnixNano()-lifetime.Nanoseconds() < created {
			countryCodes[country] = created
		}
	}

	r.Countries = countryCodes
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

// CleanUpIPs removes expired IP addresses from the RemoteClient's IPs map.
// If the IPs map does not exist or is empty, it does nothing.
// It iterates over the IP addresses in the map, and for each address, checks if its lifetime
// exceeds the configured Redis TTL. If it does, the address is removed from the IPs map.
// The cleaning logic is based on the current timestamp and the created timestamp for each IP address.
// If the RemoteClient does not have an IPs map, it creates an empty map.
func (r *RemoteClient) CleanUpIPs() {
	if !r.haveIPs() {
		return
	}

	ips := make(TTLStringMap)

	for ipAddress, created := range r.IPs {
		lifetime := time.Duration(config.RedisTTL) * time.Second

		if time.Now().UnixNano()-lifetime.Nanoseconds() < created {
			ips[ipAddress] = created
		}
	}

	r.IPs = ips
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

// AddCountryCode adds a country code to the RemoteClient's Countries map.
// If the country code is empty, it does nothing.
// If the RemoteClient is not locked, it cleans up the Countries using the CleanUpCountries method.
// If the Countries map does not exist, it creates one.
// Finally, it adds the country code with the current timestamp to the Countries map.
func (r *RemoteClient) AddCountryCode(countryCode string) {
	if countryCode == "" {
		return
	}

	if !r.Locked {
		r.CleanUpCountries()
	}

	if !r.haveCountries() {
		r.Countries = make(TTLStringMap)
	}

	r.Countries[countryCode] = time.Now().UnixNano()
}

// AddHomeCountryCode adds a home country code to the RemoteClient's HomeCountries map.
// If the country code is empty, it does nothing.
// If the RemoteClient does not have a HomeCountries map, it creates one.
// If the RemoteClient is not locked, it cleans up the HomeCountries using the CleanUpHomeCountries method.
// If the HomeCountries map does not exist, it creates one.
// Finally, it adds the country code with the current timestamp to the HomeCountries' Countries map.
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

// AddIPAddress adds an IP address to the RemoteClient's IPs map.
// If the RemoteClient is not locked, it cleans up the IPs using the CleanUpIPs method.
// If the IPs map does not exist, it creates one.
// Finally, it adds the ipAddress with the current timestamp to the IPs map.
func (r *RemoteClient) AddIPAddress(ipAddress string) {
	if !r.Locked {
		r.CleanUpIPs()
	}

	if !r.haveIPs() {
		r.IPs = make(TTLStringMap)
	}

	r.IPs[ipAddress] = time.Now().UnixNano()
}

// AddHomeIPAddress adds a home IP address to the RemoteClient's HomeCountries map.
// If the RemoteClient does not have a HomeCountries map, it creates one.
// If the RemoteClient is not locked, it cleans up the HomeIPs using the CleanUpHomeIPs method.
// If the HomeCountries map does not exist, it creates one.
// Finally, it adds the ipAddress with the current timestamp to the HomeCountries' IPs map.
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

// logNetworkCheck logs a debug message indicating that a network check is being performed.
// The function takes three parameters: ip (the IP address being checked), network (the network being checked against the IP),
// and guid (a unique identifier for the network check).
// The function uses the logger variable to log the debug message, which contains the guid and a message indicating the IP
// and network being checked.
// The logger variable should be properly initialized before invoking this function.
// The function does not return any value.
func logNetworkCheck(ip, network, guid string) {
	level.Debug(logger).Log("guid", guid, "msg", fmt.Sprintf("Checking: %s -> %s", ip, network))
}

// handleError logs an error message indicating that the provided configNet is not a network.
// The function uses a logger to log the error message, along with the GUID and the error description.
// The logger is a global variable and should be properly initialized before invoking this function.
// The function does not return any value.
func handleError(guid, configNet string, err error) {
	level.Error(logger).Log("guid", guid, "msg", "%s is not a network", configNet, "error", err)
}

// initializePolicy initializes the sender and clientIP variables by extracting the values from the
// policyRequest map. It checks if the request is "smtpd_access_policy" and returns an error
// if it's not. It determines the user attribute to use based on the configuration and checks if
// the sender and clientIP are present in the policyRequest map. If any of them is missing or
// empty, it returns an error. Finally, it returns the sender, clientIP, and nil error.
func initializePolicy(policyRequest map[string]string) (string, string, error) {
	request, found := policyRequest["request"]
	if !found || request != "smtpd_access_policy" {
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

	clientIP, found := policyRequest["client_address"]
	if !found || len(clientIP) == 0 {
		return "", "", errPolicyProtocol
	}

	return sender, clientIP, nil
}

// checkIgnoreNets checks if the clientIP should be ignored based on the ignoreNets configuration.
// It iterates through the ignoreNets list and performs the following checks:
//   - If the ignoreNet is a valid IP address, it compares it with the clientIP. If they are equal, it logs the IP address
//     found in ignore-networks and returns true.
//   - If the ignoreNet is a valid CIDR notation, it checks if the clientIP is within the network. If it is, it logs the IP
//     address found in ignore-networks and returns true.
//   - If the ignoreNet is neither a valid IP address nor a valid CIDR notation, it calls the handleError function with
//     the errorHandlerGUID, ignoreNet, and the error indicating that ignoreNet is not a network. It then continues to the
//     next iteration.
//
// If none of the ignoreNets matches the clientIP, it returns false.
func checkIgnoreNets(ignoreNets []string, clientIP, guid string) bool {
	for _, ignoreNet := range ignoreNets {
		ip := net.ParseIP(ignoreNet)
		if ip == nil {
			_, network, err := net.ParseCIDR(ignoreNet)
			if err != nil {
				handleError(guid, ignoreNet, err)

				continue
			}

			logNetworkCheck(clientIP, network.String(), guid)

			if network.Contains(net.ParseIP(clientIP)) {
				level.Info(logger).Log(
					"guid", guid,
					"msg", "IP address found in ignore-networks",
					"client_address", clientIP,
					"ignore_networks", ignoreNet,
				)

				return true
			}
		}

		logNetworkCheck(clientIP, ignoreNet, guid)

		if clientIP == ignoreNet {
			level.Info(logger).Log(
				"guid", guid,
				"msg", "IP address found in ignore-networks",
				"client_address", clientIP,
				"ignore_networks", ignoreNet,
			)

			return true
		}
	}

	return false
}

// checkUserInLDAP checks if the user is known in the LDAP.
// It takes the sender's name and the guid as input parameters.
// It returns true if the user is known in the LDAP, otherwise it returns false.
// If there is an error while checking in the LDAP, it returns true and the error.
// It relies on the configuration value of UseLDAP to determine whether to perform the check or not.
// It sends an LDAP request to ldapRequestChan to check the user in the LDAP.
// It waits for an LDAP reply on ldapReplyChan and checks the reply.
// If the user is not found in the LDAP and the error result code is LDAPResultNoSuchObject,
// it logs an info message with the GUID and sender's name and returns false with nil error.
// If there is an error while checking in the LDAP and the error result code is not LDAPResultNoSuchObject,
// it logs an error message with the GUID and the LDAP error and returns true with the LDAP error.
// If the user is found in the LDAP, it retrieves the user's name from the result attributes and logs a debug message
// with the GUID and the sender's name. It then returns true with nil error.
// If the UseLDAP configuration value is false, the function returns false with nil error.
func checkUserInLDAP(sender, guid string) (bool, error) {
	if !config.UseLDAP {
		return false, nil
	}

	ldapReplyChan := make(chan *LdapReply)
	ldapRequest := &LdapRequest{
		username:  sender,
		guid:      &guid,
		replyChan: ldapReplyChan,
	}

	ldapRequestChan <- ldapRequest

	ldapReply := <-ldapReplyChan

	if ldapReply.err != nil {
		var ldapError *ldap.Error
		if errors.As(ldapReply.err, &ldapError) && ldapError.ResultCode == uint16(ldap.LDAPResultNoSuchObject) {
			level.Info(logger).Log("guid", guid, "msg", fmt.Sprintf("User '%s' does not exist", sender))

			return false, nil
		}

		level.Error(logger).Log("guid", guid, "error", ldapReply.err.Error())

		return true, ldapReply.err
	}

	if resultAttr, mapKeyFound := ldapReply.result[config.LdapConf.SearchAttributes[ldapSingleValue]]; mapKeyFound {
		level.Debug(logger).Log("guid", guid, "msg", fmt.Sprintf("User '%s' found in LDAP", sender))

		sender = resultAttr[ldapSingleValue].(string)

		return true, nil
	}

	return false, nil
}

// checkUserInCDB checks if the user is known in the CDB.
// It takes the sender's name and the GUID as input parameters.
// It returns true if the user is known in the CDB, otherwise it returns false.
// If there is an error while checking in the CDB, it returns false and the error.
// It relies on the configuration value of UseCDB to determine whether to perform the check or not.
// It internally uses the cdbStore to load the CDB data.
// If the user is found in the CDB, it logs a debug message with the GUID and sender's name.
// The function returns an error if there is an error while getting the user data from the CDB.
// If the UseCDB configuration value is false, the function returns false and nil error.
func checkUserInCDB(sender string, guid string) (bool, error) {
	if !config.UseCDB {
		return false, nil
	}

	if db := cdbStore.Load().(*cdb.CDB); db != nil {
		value, err := db.Get([]byte(sender))
		if err != nil {
			return false, err
		}

		if value != nil {
			level.Debug(logger).Log("guid", guid, "msg", fmt.Sprintf("User '%s' found in CDB", sender))

			return true, nil
		}
	}

	return false, nil
}

// fetchRemoteClient fetches the RemoteClient object associated with a given sender.
// It retrieves the client object from Redis using the provided sender and Redis prefix.
// If the object is found in Redis, it is unmarshaled into a RemoteClient object.
// The function returns the fetched RemoteClient object and any encountered errors.
func fetchRemoteClient(sender string) (*RemoteClient, error) {
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
	if remoteClient.haveIPs() {
		for ipAddress, date := range remoteClient.IPs {
			level.Debug(logger).Log("guid", guid, "ip_address", ipAddress, "timestamp", date2String(date))
		}
	}

	if remoteClient.haveHomeIPs() {
		for ipAddress, date := range remoteClient.HomeCountries.IPs {
			level.Debug(logger).Log("guid", guid, "home_ip_address", ipAddress, "timestamp", date2String(date))
		}
	}
}

// logCountryDetails logs the country details for a remote client.
// If the country code is not present, it logs a debug message with the client IP.
// If the remote client has countries, it logs the country codes and timestamps.
// If the remote client has home countries, it logs the home country codes and timestamps.
func logCountryDetails(remoteClient *RemoteClient, countryCode, clientIP, guid string) {
	if countryCode == "" {
		level.Debug(logger).Log("guid", guid, "msg", "No country code present", "client_address", clientIP)
	} else {
		if remoteClient.haveCountries() {
			for country, date := range remoteClient.Countries {
				level.Debug(logger).Log("guid", guid, "country_code", country, "timestamp", date2String(date))
			}
		}
		if remoteClient.haveHomeCountries() {
			for country, date := range remoteClient.HomeCountries.Countries {
				level.Debug(logger).Log("guid", guid, "home_country_code", country, "timestamp", date2String(date))
			}
		}
	}
}

// applyCustomSettings applies custom settings based on the sender from the given custom settings.
// The allowedMaxIPs, allowedMaxCountries, trustedIPs, trustedCountries, homeCountries, allowedMaxHomeIPs,
// and allowedMaxHomeCountries variables are updated with the corresponding values from the custom settings.
func applyCustomSettings(customSettings *CustomSettings, sender string, allowedMaxIPs, allowedMaxCountries *int, trustedIPs, trustedCountries *[]string, homeCountries *[]string, allowedMaxHomeIPs, allowedMaxHomeCountries *int) {
	if customSettings != nil && len(customSettings.Data) > 0 {
		for _, setting := range customSettings.Data {
			if setting.Sender != sender {
				continue
			}

			if setting.IPs > 0 {
				*allowedMaxIPs = setting.IPs
			}

			if setting.Countries > 0 {
				*allowedMaxCountries = setting.Countries
			}

			if len(setting.TrustedIPs) > 0 {
				*trustedIPs = setting.TrustedIPs
			}

			if len(setting.TrustedCountries) > 0 {
				*trustedCountries = setting.TrustedCountries
			}

			if setting.HomeCountries != nil && len(setting.HomeCountries.Codes) > 0 {
				*homeCountries = setting.HomeCountries.Codes

				if setting.HomeCountries.IPs > 0 {
					*allowedMaxHomeIPs = setting.HomeCountries.IPs
				}

				if setting.HomeCountries.Countries > 0 {
					*allowedMaxHomeCountries = setting.HomeCountries.Countries
				}
			}

			break
		}
	}
}

// applyHomeSettings processes the home countries for a remote client.
//
// It checks if the given list of home countries contains the provided country code.
// If a match is found, the client's home IP address and country code are updated,
// and the function returns true. Otherwise, it returns false.
//
// Parameters:
// - remoteClient: The remote client for which to process the home countries.
// - homeCountries: The list of home countries to check.
// - countryCode: The country code to match against the home countries.
// - clientIP: The IP address of the client.
// - guid: The unique identifier of the client.
func applyHomeSettings(remoteClient *RemoteClient, homeCountries []string, countryCode, clientIP, guid string) {
	for _, homeCountry := range homeCountries {
		level.Debug(logger).Log("guid", guid, "msg", "Checking", "home_country", homeCountry)

		if strings.ToUpper(homeCountry) != countryCode {
			continue
		}

		level.Debug(logger).Log("guid", guid, "msg", "Country matched", "home_country", homeCountry)
		remoteClient.AddHomeIPAddress(clientIP)
		remoteClient.AddHomeCountryCode(countryCode)

		break
	}
}

// checkCountryPolicy checks if the country policy allows the remote client to proceed.
// It compares the given countryCode with the trustedCountries slice to determine if the country is trusted.
// If the country is trusted, or the number of countries in the remote client exceeds the allowed maximum countries,
// or the number of home countries in the remote client exceeds the allowed maximum home countries, the function returns true.
// If the policy allows permanent blocking, the function sets the locked status of the remote client to true.
// Returns a boolean indicating whether the country triggered the policy check or not.
func checkCountryPolicy(remoteClient *RemoteClient, trustedCountries []string, countryCode string, policyResponse *PolicyResponse, allowedMaxCountries, allowedMaxHomeCountries int, guid string) bool {
	if countryCode == "" {
		return false
	}

	if len(trustedCountries) > 0 {
		if isTrustedCountry(trustedCountries, countryCode, guid) {
			// client country code is trusted, ignore other checks
			return false
		}

		// client country code is not trusted
		policyResponse.fired = true
		if config.BlockPermanent {
			remoteClient.Locked = true
		}

		return true
	}

	// Proceed with other checks if no trusted country codes
	if len(remoteClient.Countries) > allowedMaxCountries ||
		(remoteClient.haveHomeCountries() && len(remoteClient.HomeCountries.Countries) > allowedMaxHomeCountries) {

		policyResponse.fired = true
		if config.BlockPermanent {
			remoteClient.Locked = true
		}

		return true
	}

	return false
}

// checkIPsPolicy checks if the client's IP address matches the policy criteria.
// It takes the client's remoteClient object, a list of trusted IP addresses,
// the client's IP address, a policyResponse object, and the maximum number of allowed IP addresses and home IP addresses as input.
// If the client's IP address is not trusted or the number of IP addresses or home IP addresses exceeds the allowed maximums,
// the function updates the policyResponse object and locks the remoteClient account if necessary.
// It returns true if the policy is violated, false otherwise.
func checkIPsPolicy(remoteClient *RemoteClient, trustedIPs []string, clientIP string, policyResponse *PolicyResponse, allowedMaxIPs, allowedMaxHomeIPs int, guid string) bool {
	if clientIP == "" {
		return false
	}

	// Check if clientIP is in trustedIPs
	if len(trustedIPs) > 0 {
		if isTrustedIP(trustedIPs, clientIP, guid) {
			// clientIP is trusted, ignore other checks
			return false
		}

		// clientIP is not trusted
		policyResponse.fired = true
		if config.BlockPermanent {
			remoteClient.Locked = true
		}

		return true
	}

	// Proceed with other checks if no trusted IPs
	if len(remoteClient.IPs) > allowedMaxIPs ||
		(remoteClient.haveHomeIPs() && len(remoteClient.HomeCountries.IPs) > allowedMaxHomeIPs) {

		policyResponse.fired = true
		if config.BlockPermanent {
			remoteClient.Locked = true
		}

		return true
	}

	return false
}

// isTrustedCountry checks if the given countryCode is in the list of trusted countries.
// It iterates over the trustedCountries slice and compares each country code with the countryCode.
// If a match is found, it returns true, otherwise false.
// The function logs debug messages for each checked country.
// Returns a boolean indicating whether the country is trusted or not.
func isTrustedCountry(trustedCountries []string, countryCode, guid string) bool {
	for _, trustedCountry := range trustedCountries {
		level.Debug(logger).Log("guid", guid, "msg", "Checking", "trusted_country", trustedCountry)

		if strings.ToUpper(trustedCountry) != countryCode {
			continue
		}

		level.Debug(logger).Log("guid", guid, "msg", "Country matched", "trusted_country", trustedCountry)

		return true
	}

	return false
}

// isTrustedIP is a function that checks if the client's IP address is considered trusted.
// It takes a list of trusted IP addresses, the client's IP address, and a GUID as input.
// It iterates through the list of trusted IP addresses and checks if the client's IP address matches any of them.
// If an IP address is found, it returns true. Otherwise, it returns false.
// The function also calls the networkContainsIP function to check if the client's IP address is within a trusted network range.
// If the trusted IP address cannot be parsed, it logs an error and returns false.
// If the IP address is found within the trusted network, it logs a success message and returns true.
// The function makes use of the net package to parse IP addresses and networks.
func isTrustedIP(trustedIPs []string, clientIP string, guid string) bool {
	matchIP := false
	ipAddress := net.ParseIP(clientIP)

	for _, trustedIPOrNet := range trustedIPs {
		if net.ParseIP(trustedIPOrNet) != nil {
			matchIP = ipAddress.String() == trustedIPOrNet
		} else {
			if networkContainsIP(trustedIPOrNet, ipAddress, guid) {
				matchIP = true
			}
		}

		if matchIP {
			break
		}
	}

	return matchIP
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
		level.Error(logger).Log("guid", guid, "msg", "Not a trusted network", "network", trustedIPOrNet, "error", err.Error())

		return false
	}

	level.Debug(logger).Log("guid", guid, "msg", "Checking", "ip_address", ipAddress.String(), "trusted_network", network.String())

	if network.Contains(ipAddress) {
		level.Debug(logger).Log("guid", guid, "msg", "IP matched", "ip_address", ipAddress.String())

		return true
	}

	return false
}

// evaluatePolicy checks the country and IP address policies for a remote client
// and updates the PolicyResponse accordingly. If the policies require any actions,
// the function returns true.
//
// The function takes the following parameters:
// - remoteClient: a pointer to a RemoteClient object representing the remote client
// - trustedIPs: a slice of trusted IP addresses
// - trustedCountries: a slice of trusted country codes
// - countryCode: a string representing the country code of the client
// - allowedMaxCountries: an int representing the maximum number of countries allowed
// - allowedMaxHomeCountries: an int representing the maximum number of home countries allowed
// - allowedMaxIPs: an int representing the maximum number of IP addresses allowed
// - allowedMaxHomeIPs: an int representing the maximum number of home IP addresses allowed
// - policyResponse: a pointer to a PolicyResponse object where the responses are updated
// - clientIP: a string representing the IP address of the client
// - guid: a string representing a unique identifier for the client
//
// The function first calls the checkCountryPolicy function to check the country policy
// and updates the PolicyResponse if necessary. Then it calls the checkIPsPolicy function
// to check the IP address policy and updates the PolicyResponse if necessary. If either
// of the policies require any actions, the function sets requireActions to true and
// returns it. Otherwise, it returns false.
//
// Example usage:
//
//	evaluatePolicy(remoteClient, trustedIPs, trustedCountries, countryCode,
//	                 allowedMaxCountries, allowedMaxHomeCountries, allowedMaxIPs,
//	                 allowedMaxHomeIPs, policyResponse, clientIP, guid)
func evaluatePolicy(remoteClient *RemoteClient, trustedIPs, trustedCountries []string, countryCode string, allowedMaxCountries, allowedMaxHomeCountries, allowedMaxIPs, allowedMaxHomeIPs int, policyResponse *PolicyResponse, clientIP, guid string) bool {
	var requireActions bool

	if checkCountryPolicy(remoteClient, trustedCountries, countryCode, policyResponse, allowedMaxCountries, allowedMaxHomeCountries, guid) ||
		checkIPsPolicy(remoteClient, trustedIPs, clientIP, policyResponse, allowedMaxIPs, allowedMaxHomeIPs, guid) {
		requireActions = true
	}

	return requireActions
}

// checkUserKnown checks if the user is known by checking in LDAP and CDB.
// If the user is known in LDAP, it returns true and nil error.
// If the user is not known in LDAP, it checks in CDB.
// If the user is known in CDB, it returns true and nil error.
// If the user is not known in CDB, it returns false and nil error.
// If there is an error while checking in LDAP or CDB, it returns false and the error.
func checkUserKnown(sender, guid string) (bool, error) {
	if config.ForceUserKnown {
		return true, nil
	}

	userKnown, err := checkUserInLDAP(sender, guid)
	if err != nil {
		return false, err
	}

	if !userKnown {
		userKnown, err = checkUserInCDB(sender, guid)
		if err != nil {
			return false, err
		}
	}

	return userKnown, nil
}

// fetchAndLogRemoteClient fetches a remote client based on the sender string,
// logs the client details and country details using the provided sender, client IP, country code, and GUID.
// It returns the fetched remote client and any errors encountered.
func fetchAndLogRemoteClient(sender, clientIP, countryCode, guid string) (*RemoteClient, error) {
	remoteClient, err := fetchRemoteClient(sender)
	if err != nil {
		return nil, err
	}

	logClientDetails(remoteClient, guid)
	logCountryDetails(remoteClient, countryCode, clientIP, guid)

	return remoteClient, nil
}

// handleClientActions handles the client actions based on the configuration and requirements.
// If the RunActions configuration is true and requireActions is true, it calls the runOperatorAction function
// with the given remoteClient, sender, userKnown, and guid parameters.
// If runOperatorAction returns an error, it logs the error message with the guid value.
// Note that handleClientActions does not return any value.
func handleClientActions(remoteClient *RemoteClient, sender string, userKnown bool, guid string, requireActions bool) {
	if config.RunActions && requireActions {
		err := runOperatorAction(remoteClient, sender, userKnown, guid)
		if err != nil {
			level.Error(logger).Log("guid", guid, "error", err.Error())
		}
	}
}

// runOperatorAction processes the "operator" action for the given remote client.
// It checks if the "operator" action should be run based on the configuration and the existing actions list.
// If it should be run, it creates an instance of EmailOperator and calls the Call method.
// If the Call method returns an error, it is returned as an error from the function.
// After successfully running the action, the "operator" action is appended to the actions list of the remote client.
// Returns nil if the action is not run or if it is run successfully.
func runOperatorAction(remoteClient *RemoteClient, sender string, userKnown bool, guid string) error {
	if userKnown && config.RunActionOperator && shouldRunOperator(remoteClient) {
		action := &EmailOperator{}
		if err := action.Call(sender); err != nil {
			return err
		}

		level.Debug(logger).Log("guid", guid, "msg", "Action 'operator' finished successfully")

		remoteClient.Actions = append(remoteClient.Actions, "operator")
	}

	return nil
}

// shouldRunOperator determines whether the "operator" action should be run for the given remote client.
// It checks if the "operator" action already exists in the actions list of the remote client.
// If it does, it returns false to indicate that the action should not be run.
// If it doesn't, it returns true to indicate that the action should be run.
func shouldRunOperator(remoteClient *RemoteClient) bool {
	for _, actionItem := range remoteClient.Actions {
		if actionItem == "operator" {
			return false
		}
	}

	return true
}

// updateRedisCache updates the Redis cache with the provided sender and RemoteClient information.
// It marshals the RemoteClient into JSON format and sets it in the Redis cache under a key derived
// from the sender. It also sets an expiration time for the cache entry based on the RedisTTL
// configuration value. If the RemoteClient is locked, it additionally persists the cache entry.
// It returns an error if any of the Redis operations fail.
func updateRedisCache(sender string, remoteClient *RemoteClient) error {
	redisValue, err := json.Marshal(remoteClient)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s%s", config.RedisPrefix, sender)

	if err = redisHandle.Set(ctx, key, redisValue, time.Duration(0)).Err(); err != nil {
		return err
	}

	if remoteClient.Locked {
		if err = redisHandle.Persist(ctx, key).Err(); err != nil {
			return err
		}
	} else {
		if err = redisHandle.Expire(ctx, key, time.Duration(config.RedisTTL)*time.Second).Err(); err != nil {
			return err
		}
	}

	return nil
}

// logPolicyResult logs the policy result using the provided policy response, remote client, sender,
// trusted countries, trusted IPs, and GUID. It uses the level.Info function from the logger
// to log the information with the following fields: guid, user attribute,
// foreign countries seen, home countries seen, home countries defined, trusted countries defined,
// total countries, allowed max foreign countries, allowed max home countries, foreign IPs seen,
// home IPs seen, trusted IPs defined, total IPs, allowed max foreign IPs, allowed max home IPs,
// and action status.
func logPolicyResult(policyResponse *PolicyResponse, remoteClient *RemoteClient, sender string, trustedCountries, trustedIPs []string, guid string) {
	level.Info(logger).Log("guid", guid,
		getUserAttribute(), sender,
		"current_client_ip", policyResponse.currentClientIP,
		"current_country_code", policyResponse.currentCountryCode,
		"foreign_countries_seen", getForeignCountriesSeen(remoteClient),
		"home_countries_seen", getHomeCountriesSeen(remoteClient),
		"home_countries_defined", getHouseCountries(),
		"trusted_countries_defined", getTrustedCountries(trustedCountries),
		"total_countries", getTotalCountries(remoteClient, policyResponse),
		"allowed_max_foreign_countries", config.MaxCountries,
		"allowed_max_home_countries", config.MaxHomeCountries,
		"foreign_ips_seen", getForeignIPsSeen(remoteClient),
		"home_ips_seen", getHomeIPsSeen(remoteClient),
		"trusted_ips_defined", getTrustedIPs(trustedIPs),
		"total_ips", getTotalIPs(remoteClient, policyResponse),
		"allowed_max_foreign_ips", config.MaxIPs,
		"allowed_max_home_ips", config.MaxHomeIPs,
		"action", getActionStatus(policyResponse),
	)
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
	if remoteClient.haveCountries() {
		var countries []string

		for country := range remoteClient.Countries {
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

	if remoteClient.haveCountries() {
		sum = len(remoteClient.Countries)
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
	if remoteClient.haveIPs() {
		var ips []string
		for ip := range remoteClient.IPs {
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
// of the trusted IPs separated by commas. If the trustedIPs slice is empty,
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

	if remoteClient.haveIPs() {
		sum = len(remoteClient.IPs)
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

	return "ok"
}

// setCurrentValues sets the current client IP and country code in the PolicyResponse object.
// It takes the IP address, country code, and a pointer to the PolicyResponse object as input parameters.
// It assigns the IP address to the `currentClientIP` field and the country code to the `currentCountryCode` field
// of the PolicyResponse object.
func setCurrentValues(ip string, code string, policyResponse *PolicyResponse) {
	policyResponse.currentClientIP = ip
	policyResponse.currentCountryCode = code
}

// getPolicyResponse is a function that takes a policyRequest map and a guid string as input parameters
// and returns a policyResponse pointer and an error as output. It initializes a PolicyResponse object,
// initializes the sender, clientIP, and err variables by calling the initializePolicy function with the
// policyRequest map, checks if the clientIP should be ignored based on the ignoreNets configuration, checks
// if the sender is known by calling the checkUserKnown function, gets the country code of the clientIP by
// calling the getCountryCode function, fetches and logs the remote client by calling the fetchAndLogRemoteClient
// function, applies custom settings based on the sender by calling the applyCustomSettings function, determines
// if the client is at home by calling the applyHomeSettings function, processes the remote client's countries
// by calling the evaluatePolicy function, handles the client actions based on the remoteClient, sender,
// userKnown, and requireActions variables by calling the handleClientActions function, updates the Redis cache
// by calling the updateRedisCache function, logs the policy result by calling the logPolicyResult function,
// and finally returns the policyResponse and nil error.
func getPolicyResponse(policyRequest map[string]string, guid string) (policyResponse *PolicyResponse, err error) {
	var (
		trustedCountries        []string
		trustedIPs              []string
		allowedMaxIPs           = config.MaxIPs
		allowedMaxCountries     = config.MaxCountries
		homeCountries           = config.HomeCountries
		allowedMaxHomeIPs       = config.MaxHomeIPs
		allowedMaxHomeCountries = config.MaxHomeCountries
	)

	policyResponse = &PolicyResponse{}

	sender, clientIP, err := initializePolicy(policyRequest)
	if err != nil {
		return nil, err
	}

	if checkIgnoreNets(config.IgnoreNets, clientIP, guid) {
		policyResponse.whitelisted = true

		return
	}

	userKnown, err := checkUserKnown(sender, guid)
	if err != nil {
		return policyResponse, err
	}

	countryCode := getCountryCode(clientIP)

	setCurrentValues(clientIP, countryCode, policyResponse)

	remoteClient, err := fetchAndLogRemoteClient(sender, clientIP, countryCode, guid)
	if err != nil {
		return nil, err
	}

	applyCustomSettings(
		customSettingsStore.Load().(*CustomSettings),
		sender,
		&allowedMaxIPs,
		&allowedMaxCountries,
		&trustedIPs,
		&trustedCountries,
		&homeCountries,
		&allowedMaxHomeIPs,
		&allowedMaxHomeCountries,
	)

	applyHomeSettings(remoteClient, homeCountries, countryCode, clientIP, guid)

	requireActions := evaluatePolicy(
		remoteClient,
		trustedIPs,
		trustedCountries,
		countryCode,
		allowedMaxCountries,
		allowedMaxHomeCountries,
		allowedMaxIPs,
		allowedMaxHomeIPs,
		policyResponse,
		clientIP,
		guid,
	)

	if remoteClient.Locked {
		policyResponse.fired = true
		requireActions = true
	}

	handleClientActions(remoteClient, sender, userKnown, guid, requireActions)

	err = updateRedisCache(sender, remoteClient)
	if err != nil {
		return nil, err
	}

	logPolicyResult(policyResponse, remoteClient, sender, trustedCountries, trustedIPs, guid)

	return policyResponse, nil
}
