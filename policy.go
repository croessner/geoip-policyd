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

type TTLStringMap map[string]int64

type RedisHomeCountries struct {
	IPs       TTLStringMap `redis:"ips"`       // All known home IP addresses
	Countries TTLStringMap `redis:"countries"` // All known home country codes
}

type PolicyResponse struct {
	fired                bool
	whitelisted          bool
	totalIPs             int
	totalCountries       int
	homeIPsSeen          []string
	foreignIPsSeen       []string
	homeCountriesSeen    []string
	foreignCountriesSeen []string
}

type RemoteClient struct {
	IPs           TTLStringMap        `redis:"ips"`            // All known IP addresses
	Countries     TTLStringMap        `redis:"countries"`      // All known country codes
	HomeCountries *RedisHomeCountries `redis:"home_countries"` // All known home IPs and countries
	Actions       []string            `redis:"actions"`        // All actions that may have run
	Locked        bool                `redis:"locked"`         // Account is permanentley locked
}

func (r *RemoteClient) haveHome() bool {
	return r.HomeCountries != nil
}

func (r *RemoteClient) haveHomeCountries() bool {
	if r.haveHome() {
		return r.HomeCountries.Countries != nil
	}

	return false
}

func (r *RemoteClient) haveHomeIPs() bool {
	if r.haveHome() {
		return r.HomeCountries.IPs != nil
	}

	return false
}

func (r *RemoteClient) haveCountries() bool {
	return r.Countries != nil
}

func (r *RemoteClient) haveIPs() bool {
	return r.IPs != nil
}

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

func (r *RemoteClient) AddIPAddress(ipAddress string) {
	if !r.Locked {
		r.CleanUpIPs()
	}

	if !r.haveIPs() {
		r.IPs = make(TTLStringMap)
	}

	r.IPs[ipAddress] = time.Now().UnixNano()
}

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

//nolint:gocognit,gocyclo,maintidx // This function implements the main logic of the policy service
func getPolicyResponse(policyRequest map[string]string, guid string) (policyResponse *PolicyResponse, err error) {
	var (
		isHome                  bool
		requireActions          bool
		mapKeyFound             bool
		matchIP                 bool
		userKnown               bool
		request                 string
		sender                  string
		clientIP                string
		redisValue              []byte
		trustedCountries        []string
		trustedIPs              []string
		network                 *net.IPNet
		remoteClient            *RemoteClient
		allowedMaxIPs           = config.MaxIPs
		allowedMaxCountries     = config.MaxCountries
		homeCountries           = config.HomeCountries
		allowedMaxHomeIPs       = config.MaxHomeIPs
		allowedMaxHomeCountries = config.MaxHomeCountries
	)

	policyResponse = &PolicyResponse{}

	userAttribute := Sender
	if config.UseSASLUsername {
		userAttribute = SASLUsername
	}

	if request, mapKeyFound = policyRequest["request"]; !mapKeyFound {
		err = errPolicyProtocol

		return
	}

	if request != "smtpd_access_policy" {
		err = errPolicyProtocol

		return
	}

	if sender, mapKeyFound = policyRequest[userAttribute]; !mapKeyFound {
		err = errPolicyProtocol

		return
	}

	if len(sender) == 0 {
		err = errPolicyProtocol

		return
	}

	if clientIP, mapKeyFound = policyRequest["client_address"]; !mapKeyFound {
		err = errPolicyProtocol

		return
	}

	if clientIP == "" {
		err = errPolicyProtocol

		return
	}

	for index := range config.IgnoreNets {
		if net.ParseIP(config.IgnoreNets[index]) == nil {
			_, network, err = net.ParseCIDR(config.IgnoreNets[index])
			if err != nil {
				level.Error(logger).Log("guid", guid, "msg", "%s is not a network", config.IgnoreNets[index], "error", err)

				// Reset error
				err = nil

				continue
			}

			level.Debug(logger).Log(
				"guid", guid, "msg", fmt.Sprintf("Checking: %s -> %s", clientIP, network.String()),
			)

			if network.Contains(net.ParseIP(clientIP)) {
				level.Info(logger).Log(
					"guid", guid,
					"msg", "IP address found in ignore-networks",
					"client_address", clientIP,
					"ignore_networks", config.IgnoreNets[index],
				)

				matchIP = true

				break
			}
		} else {
			level.Debug(logger).Log(
				"guid", guid, "msg", fmt.Sprintf("Checking: %s -> %s", clientIP, config.IgnoreNets[index]))

			if clientIP == config.IgnoreNets[index] {
				level.Info(logger).Log(
					"guid", guid,
					"msg", "IP address found in ignore-networks",
					"client_address", clientIP,
					"ignore_networks", config.IgnoreNets[index],
				)

				matchIP = true

				break
			}
		}
	}

	if matchIP {
		policyResponse.whitelisted = true

		return
	}

	if config.UseLDAP {
		var (
			ldapReply   *LdapReply
			ldapRequest *LdapRequest
			resultAttr  []any
		)

		ldapReplyChan := make(chan *LdapReply)

		ldapRequest = &LdapRequest{}

		ldapRequest.username = sender
		ldapRequest.guid = &guid
		ldapRequest.replyChan = ldapReplyChan

		ldapRequestChan <- ldapRequest

		ldapReply = <-ldapReplyChan

		if ldapReply.err != nil {
			var ldapError *ldap.Error

			if errors.As(ldapReply.err, &ldapError) {
				if ldapError.ResultCode == uint16(ldap.LDAPResultNoSuchObject) {
					level.Info(logger).Log("guid", guid, "msg", fmt.Sprintf("User '%s' does not exist", sender))

					err = nil

					return
				}
			}

			level.Error(logger).Log("guid", guid, "error", ldapReply.err.Error())

			return policyResponse, ldapReply.err
		} else {
			if resultAttr, mapKeyFound = ldapReply.result[config.LdapConf.SearchAttributes[ldapSingleValue]]; mapKeyFound {
				level.Debug(logger).Log(
					"guid", guid,
					"msg", fmt.Sprintf("User '%s' found in LDAP", sender),
				)

				// LDAP single value
				sender = resultAttr[ldapSingleValue].(string)
				userKnown = true
			}
		}
	}

	if config.UseCDB {
		var (
			value []byte
			db    *cdb.CDB
		)

		if db = cdbStore.Load().(*cdb.CDB); db != nil {
			value, err = db.Get([]byte(sender))
			if err != nil {
				return
			}

			if value != nil {
				level.Debug(logger).Log(
					"guid", guid,
					"msg", fmt.Sprintf("User '%s' found in CDB", sender),
				)

				userKnown = true
			}
		}
	}

	key := fmt.Sprintf("%s%s", config.RedisPrefix, sender)
	remoteClient = &RemoteClient{}

	// Check Redis for the current sender
	if redisValue, err = redisHandleReplica.Get(ctx, key).Bytes(); err != nil {
		if !errors.Is(err, redis.Nil) {
			return
		}
	} else if err = json.Unmarshal(redisValue, remoteClient); err != nil {
		return
	}

	if remoteClient.haveIPs() {
		for ipAddress, date := range remoteClient.IPs {
			level.Debug(logger).Log(
				"guid", guid, "ip_address", ipAddress, "timestamp", date2String(date))
		}
	}

	if remoteClient.haveHomeIPs() {
		for ipAddress, date := range remoteClient.HomeCountries.IPs {
			level.Debug(logger).Log(
				"guid", guid, "home_ip_address", ipAddress, "timestamp", date2String(date))
		}
	}

	// Check current IP address country code
	countryCode := strings.ToUpper(getCountryCode(clientIP))

	if countryCode == "" {
		level.Debug(logger).Log(
			"guid", guid, "msg", "No country code present", "client_address", clientIP)
	} else {
		if remoteClient.haveCountries() {
			for country, date := range remoteClient.Countries {
				level.Debug(logger).Log(
					"guid", guid, "country_code", country, "timestamp", date2String(date))
			}
		}

		if remoteClient.haveHomeCountries() {
			for country, date := range remoteClient.HomeCountries.Countries {
				level.Debug(logger).Log(
					"guid", guid, "home_country_code", country, "timestamp", date2String(date))
			}
		}
	}

	//nolint:forcetypeassert // Global variable
	customSettings := customSettingsStore.Load().(*CustomSettings)

	if customSettings != nil {
		if len(customSettings.Data) > 0 {
			for index := range customSettings.Data {
				if customSettings.Data[index].Sender != sender {
					continue
				}

				// Override global max IPs setting with custom setting
				if customSettings.Data[index].IPs > 0 {
					allowedMaxIPs = customSettings.Data[index].IPs
				}

				// Override global max countries setting with custom setting
				if customSettings.Data[index].Countries > 0 {
					allowedMaxCountries = customSettings.Data[index].Countries
				}

				// Enforced IPs
				if len(customSettings.Data[index].TrustedIPs) > 0 {
					trustedIPs = customSettings.Data[index].TrustedIPs
				}

				// Enforced countries
				if len(customSettings.Data[index].TrustedCountries) > 0 {
					trustedCountries = customSettings.Data[index].TrustedCountries
				}

				if customSettings.Data[index].HomeCountries != nil {
					if customSettings.Data[index].HomeCountries.Codes != nil && len(customSettings.Data[index].HomeCountries.Codes) > 0 {
						// Override global home country codes setting with custom setting
						homeCountries = customSettings.Data[index].HomeCountries.Codes

						// Override global max home IPs setting with custom setting
						if customSettings.Data[index].HomeCountries.IPs > 0 {
							allowedMaxHomeIPs = customSettings.Data[index].HomeCountries.IPs
						}

						// Override global max home countries setting with custom setting
						if customSettings.Data[index].HomeCountries.Countries > 0 {
							allowedMaxHomeCountries = customSettings.Data[index].HomeCountries.Countries
						}
					}
				}

				break // First match wins!
			}
		}
	}

	if countryCode != "" && len(homeCountries) > 0 {
		for index := range homeCountries {
			level.Debug(logger).Log(
				"guid", guid, "msg", "Checking", "home_country", homeCountries[index])

			if strings.ToUpper(homeCountries[index]) != countryCode {
				continue
			}

			level.Debug(logger).Log(
				"guid", guid, "msg", "Country matched", "home_country", homeCountries[index])

			isHome = true

			remoteClient.AddHomeIPAddress(clientIP)
			remoteClient.AddHomeCountryCode(countryCode)

			break
		}
	}

	if !isHome {
		remoteClient.AddIPAddress(clientIP)
		remoteClient.AddCountryCode(countryCode)
	}

	if countryCode != "" && len(trustedCountries) > 0 {
		matchCountry := false

		for index := range trustedCountries {
			level.Debug(logger).Log(
				"guid", guid, "msg", "Checking", "trusted_country", trustedCountries[index])

			if strings.ToUpper(trustedCountries[index]) != countryCode {
				continue
			}

			level.Debug(logger).Log(
				"guid", guid, "msg", "Country matched", "trusted_country", trustedCountries[index])

			matchCountry = true

			break
		}

		if !matchCountry {
			policyResponse.fired = true
			requireActions = true

			if config.BlockPermanent {
				remoteClient.Locked = true
			}
		}
	} else if len(remoteClient.Countries) > allowedMaxCountries {
		policyResponse.fired = true
		requireActions = true

		if config.BlockPermanent {
			remoteClient.Locked = true
		}
	} else if remoteClient.haveHomeCountries() {
		if len(remoteClient.HomeCountries.Countries) > allowedMaxHomeCountries {
			policyResponse.fired = true
			requireActions = true

			if config.BlockPermanent {
				remoteClient.Locked = true
			}
		}
	}

	if len(trustedIPs) > 0 {
		matchIP = false
		ipAddress := net.ParseIP(clientIP)

		for _, trustedIPOrNet := range trustedIPs {
			trustedIP := net.ParseIP(trustedIPOrNet)
			if trustedIP == nil {
				var network *net.IPNet

				_, network, err = net.ParseCIDR(trustedIPOrNet)
				if err != nil {
					level.Error(logger).Log(
						"guid", guid, "msg", "Not a trusted network", "network", trustedIP, "error", err.Error())

					// Reset error
					err = nil

					continue
				}

				level.Debug(logger).Log(
					"guid", guid, "msg", "Checking", "ip_address", ipAddress.String(), "trusted_network", network.String())

				if network.Contains(ipAddress) {
					level.Debug(logger).Log(
						"guid", guid, "msg", "IP matched", "ip_address", ipAddress.String())

					matchIP = true

					break
				}
			} else {
				level.Debug(logger).Log(
					"guid", guid, "msg", "Checking", "ip_address", ipAddress.String(), "trusted_ip_address", trustedIP.String())

				if trustedIP.String() == ipAddress.String() {
					level.Debug(logger).Log(
						"guid", guid, "msg", "IP matched", "ip_address", ipAddress.String())

					matchIP = true

					break
				}
			}
		}

		if !matchIP {
			policyResponse.fired = true
			requireActions = true

			if config.BlockPermanent {
				remoteClient.Locked = true
			}
		}
	} else if len(remoteClient.IPs) > allowedMaxIPs {
		policyResponse.fired = true
		requireActions = true

		if config.BlockPermanent {
			remoteClient.Locked = true
		}
	} else if remoteClient.haveHomeIPs() {
		if len(remoteClient.HomeCountries.IPs) > allowedMaxHomeIPs {
			policyResponse.fired = true
			requireActions = true

			if config.BlockPermanent {
				remoteClient.Locked = true
			}
		}
	}

	if config.RunActions && requireActions {
		var action Action

		runOperator := true

		// Check: Action already priviously done.
		for _, actionItem := range remoteClient.Actions {
			if actionItem == "operator" {
				runOperator = false

				break
			}
		}

		if userKnown && config.RunActionOperator && runOperator {
			action = &EmailOperator{}
			if err = action.Call(sender); err != nil {
				level.Error(logger).Log("guid", guid, "error", err.Error())
			} else {
				level.Debug(logger).Log(
					"guid", guid, "msg", "Action 'operator' finished successfully")

				remoteClient.Actions = append(remoteClient.Actions, "operator")
			}
		}
	}

	redisValue, err = json.Marshal(remoteClient)
	if err != nil {
		return
	}

	if err = redisHandle.Set(ctx, key, redisValue, time.Duration(0)).Err(); err != nil {
		return
	}

	// For each request update the expiry timestamp
	if remoteClient.Locked {
		if err = redisHandle.Persist(ctx, key).Err(); err != nil {
			return
		}
	} else {
		if err = redisHandle.Expire(ctx, key, time.Duration(config.RedisTTL)*time.Second).Err(); err != nil {
			return
		}
	}

	level.Info(logger).Log(
		"guid", guid,
		userAttribute, sender,
		"foreign_countries_seen", func() string {
			if remoteClient.haveCountries() {
				var foreignCountriesSeen []string

				for country := range remoteClient.Countries {
					foreignCountriesSeen = append(foreignCountriesSeen, country)
				}

				policyResponse.foreignCountriesSeen = foreignCountriesSeen

				return strings.Join(foreignCountriesSeen, ",")
			}

			return "N/A"
		}(),
		"home_countries_seen", func() string {
			if remoteClient.haveHomeCountries() {
				var homeCountriesSeen []string

				for country := range remoteClient.HomeCountries.Countries {
					homeCountriesSeen = append(homeCountriesSeen, country)
				}

				policyResponse.homeCountriesSeen = homeCountriesSeen

				return strings.Join(homeCountriesSeen, ",")
			}

			return "N/A"
		}(),
		"home_countries_defined", func() string {
			if len(homeCountries) > 0 {
				return strings.Join(homeCountries, ",")
			}

			return "N/A"
		}(),
		"trusted_countries_defined", func() string {
			if len(trustedCountries) > 0 {
				return strings.Join(trustedCountries, ",")
			}

			return "N/A"
		}(),
		"total_countries", func() int {
			sum := 0

			if remoteClient.haveCountries() {
				sum = len(remoteClient.Countries)
			}

			if remoteClient.haveHomeCountries() {
				sum += len(remoteClient.HomeCountries.Countries)
			}

			policyResponse.totalCountries = sum

			return sum
		}(),
		"allowed_max_foreign_countries", allowedMaxCountries,
		"allowed_max_home_countries", allowedMaxHomeCountries,
		"foreign_ips_seen", func() string {
			if remoteClient.haveIPs() {
				var foreignIPsSeen []string

				for ipAddress := range remoteClient.IPs {
					foreignIPsSeen = append(foreignIPsSeen, ipAddress)
				}

				policyResponse.foreignIPsSeen = foreignIPsSeen

				return strings.Join(foreignIPsSeen, ",")
			}

			return "N/A"
		}(),
		"home_ips_seen", func() string {
			if remoteClient.haveHomeIPs() {
				var homeIPsSeen []string

				for ipAddress := range remoteClient.HomeCountries.IPs {
					homeIPsSeen = append(homeIPsSeen, ipAddress)
				}

				policyResponse.homeIPsSeen = homeIPsSeen

				return strings.Join(homeIPsSeen, ",")
			}

			return "N/A"
		}(),
		"trusted_ips_defined", func() string {
			if len(trustedIPs) > 0 {
				return strings.Join(trustedIPs, ",")
			}

			return "N/A"
		}(),
		"total_ips", func() int {
			sum := 0

			if remoteClient.haveIPs() {
				sum = len(remoteClient.IPs)
			}

			if remoteClient.haveHomeIPs() {
				sum += len(remoteClient.HomeCountries.IPs)
			}

			policyResponse.totalIPs = sum

			return sum
		}(),
		"allowed_max_foreign_ips", allowedMaxIPs,
		"allowed_max_home_ips", allowedMaxHomeIPs,
		"action", func() string {
			if policyResponse.fired {
				return rejectText
			}

			return "ok"
		}())

	return
}
