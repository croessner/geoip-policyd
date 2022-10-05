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
	"os"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
)

const (
	deferText  = "DEFER Service temporarily not available"
	rejectText = "REJECT Your account seems to be compromised. Please contact your support"
)

type TTLStringMap map[string]int64

type RemoteClient struct {
	IPs       TTLStringMap `redis:"ips"`       // All known IP addresses
	Countries TTLStringMap `redis:"countries"` // All known country codes
	Actions   []string     `redis:"actions"`   // All actions that may have run
	Locked    bool         `redis:"locked"`    // Account is permanentley locked
}

func (r *RemoteClient) CleanUpCountries() {
	if r.Countries == nil {
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

func (r *RemoteClient) CleanUpIPs() {
	if r.IPs == nil {
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

func (r *RemoteClient) AddCountryCode(countryCode string) {
	if !r.Locked {
		r.CleanUpCountries()
	}

	if r.Countries == nil {
		r.Countries = make(TTLStringMap)
	}

	r.Countries[countryCode] = time.Now().UnixNano()
}

func (r *RemoteClient) AddIPAddress(ipAddress string) {
	if !r.Locked {
		r.CleanUpIPs()
	}

	if r.IPs == nil {
		r.IPs = make(TTLStringMap)
	}

	r.IPs[ipAddress] = time.Now().UnixNano()
}

//nolint:gocognit,gocyclo,maintidx // This function implements the main logic of the policy service
func getPolicyResponse(policyRequest map[string]string, guid string) string {
	var (
		mapKeyFound         bool
		request             string
		sender              string
		clientIP            string
		trustedCountries    []string
		trustedIPs          []string
		err                 error
		remoteClient        RemoteClient
		allowedMaxIPs       = config.MaxIPs
		allowedMaxCountries = config.MaxCountries
		actionText          = "DUNNO"
	)

	if request, mapKeyFound = policyRequest["request"]; mapKeyFound {
		if request == "smtpd_access_policy" {
			userAttribute := "sender"
			if config.UseSASLUsername {
				userAttribute = "sasl_username"
			}

			if sender, mapKeyFound = policyRequest[userAttribute]; mapKeyFound {
				if len(sender) > 0 {
					if config.UseLDAP {
						var (
							ldapReply   LdapReply
							ldapRequest LdapRequest
							resultAttr  []string
						)

						ldapReplyChan := make(chan LdapReply)

						ldapRequest.username = sender
						ldapRequest.filter = config.LDAP.Filter
						ldapRequest.guid = guid
						ldapRequest.attributes = config.LDAP.ResultAttr
						ldapRequest.replyChan = ldapReplyChan

						ldapRequestChan <- ldapRequest

						ldapReply = <-ldapReplyChan

						if ldapReply.err != nil {
							level.Error(logger).Log("guid", guid, "error", err.Error())
						} else if resultAttr, mapKeyFound = ldapReply.result[config.LDAP.ResultAttr[0]]; mapKeyFound {
							// LDAP single value
							sender = resultAttr[0]
						}
					}

					if clientIP, mapKeyFound = policyRequest["client_address"]; mapKeyFound {
						var redisValue []byte

						key := fmt.Sprintf("%s%s", config.RedisPrefix, sender)

						// Check Redis for the current sender
						if redisValue, err = redisHandleReplica.Get(ctx, key).Bytes(); err != nil {
							if !errors.Is(err, redis.Nil) {
								level.Error(logger).Log("guid", guid, "error", err.Error())

								return fmt.Sprintf("action=%s", deferText)
							}
						} else if err = json.Unmarshal(redisValue, &remoteClient); err != nil {
							level.Error(logger).Log("guid", guid, "error", err.Error())
						}

						if config.VerboseLevel == logLevelDebug {
							if remoteClient.IPs != nil {
								for ipAddress, date := range remoteClient.IPs {
									level.Debug(logger).Log(
										"guid", guid,
										"ip_address", ipAddress,
										"timestamp_local", func() string {
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
										}())
								}
							}
						}

						remoteClient.AddIPAddress(clientIP)

						// Check current IP address country code
						countryCode := getCountryCode(clientIP)
						if countryCode == "" {
							level.Debug(logger).Log(
								"guid", guid, "msg", "No country code present", "client_address", clientIP)
						} else {
							if config.VerboseLevel == logLevelDebug {
								if remoteClient.Countries != nil {
									for country, date := range remoteClient.Countries {
										level.Debug(logger).Log(
											"guid", guid,
											"country_code", country,
											"timestamp_local", func() string {
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
											}())
									}
								}
							}

							remoteClient.AddCountryCode(countryCode)
						}

						if val := os.Getenv("GO_TESTING"); val == "" {
							//nolint:forcetypeassert // Global variable
							customSettings := customSettingsStore.Load().(*CustomSettings)
							if customSettings != nil {
								if len(customSettings.Data) > 0 {
									for _, record := range customSettings.Data {
										if record.Sender != sender {
											continue
										}

										// Override global max IPs setting with custom setting
										if record.IPs > 0 {
											allowedMaxIPs = record.IPs
										}

										// Override global max countries setting with custom setting
										if record.Countries > 0 {
											allowedMaxCountries = record.Countries
										}

										// Enforced IPs
										if len(record.TrustedIPs) > 0 {
											trustedIPs = record.TrustedIPs
										}

										// Enforced countries
										if len(record.TrustedCountries) > 0 {
											trustedCountries = record.TrustedCountries
										}

										break // First match wins!
									}
								}
							}
						}

						requireActions := false

						if len(trustedCountries) > 0 {
							matchCountry := false

							for _, trustedCountry := range trustedCountries {
								level.Debug(logger).Log(
									"guid", guid, "msg", "Checking", "trusted_country", trustedCountry)

								if trustedCountry == countryCode {
									level.Debug(logger).Log(
										"guid", guid, "msg", "Country matched", "trusted_country", trustedCountry)

									matchCountry = true

									break
								}
							}

							if !matchCountry {
								actionText = rejectText
								requireActions = true

								if config.BlockPermanent {
									remoteClient.Locked = true
								}
							}
						} else if len(remoteClient.Countries) > allowedMaxCountries {
							actionText = rejectText
							requireActions = true

							if config.BlockPermanent {
								remoteClient.Locked = true
							}
						}

						if len(trustedIPs) > 0 {
							matchIP := false
							ipAddress := net.ParseIP(clientIP)

							for _, trustedIPOrNet := range trustedIPs {
								trustedIP := net.ParseIP(trustedIPOrNet)
								if trustedIP == nil {
									var network *net.IPNet

									_, network, err = net.ParseCIDR(trustedIPOrNet)
									if err != nil {
										level.Error(logger).Log(
											"guid", guid,
											"msg", "Not a trusted network",
											"network", trustedIP,
											"error", err.Error())

										continue
									}

									level.Debug(logger).Log(
										"guid", guid,
										"msg", "Checking",
										"ip_address", ipAddress.String(),
										"trusted_network", network.String())

									if network.Contains(ipAddress) {
										level.Debug(logger).Log(
											"guid", guid, "msg", "IP matched", "ip_address", ipAddress.String())

										matchIP = true

										break
									}
								} else {
									level.Debug(logger).Log(
										"guid", guid,
										"msg", "Checking",
										"ip_address", ipAddress.String(),
										"trusted_ip_address", trustedIP.String())

									if trustedIP.String() == ipAddress.String() {
										level.Debug(logger).Log(
											"guid", guid, "msg", "IP matched", "ip_address", ipAddress.String())

										matchIP = true

										break
									}
								}
							}

							if !matchIP {
								actionText = rejectText
								requireActions = true

								if config.BlockPermanent {
									remoteClient.Locked = true
								}
							}
						} else if len(remoteClient.IPs) > allowedMaxIPs {
							actionText = rejectText
							requireActions = true

							if config.BlockPermanent {
								remoteClient.Locked = true
							}
						}

						if config.RunActions && requireActions {
							var action Action

							runOperator := true

							for _, actionItem := range remoteClient.Actions {
								if actionItem == "operator" {
									runOperator = false

									break
								}
							}

							if config.RunActionOperator && runOperator {
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
							return fmt.Sprintf("action=%s", deferText)
						}

						if err = redisHandle.Set(ctx, key, redisValue, time.Duration(0)).Err(); err != nil {
							level.Error(logger).Log("guid", guid, "error", err.Error())

							return fmt.Sprintf("action=%s", deferText)
						}

						// For each request update the expiry timestamp
						if remoteClient.Locked {
							if err = redisHandle.Persist(ctx, key).Err(); err != nil {
								level.Error(logger).Log("guid", guid, "error", err.Error())

								return fmt.Sprintf("action=%s", deferText)
							}
						} else {
							if err = redisHandle.Expire(ctx, key, time.Duration(config.RedisTTL)*time.Second).Err(); err != nil {
								level.Error(logger).Log("guid", guid, "error", err.Error())

								return fmt.Sprintf("action=%s", deferText)
							}
						}
					}
				}
			}
		}
	}

	senderKey := "sender"
	if config.UseSASLUsername {
		senderKey = "sasl_username"
	}

	level.Info(logger).Log(
		"guid", guid,
		senderKey, sender,
		"countries", func() string {
			var countries []string

			for country := range remoteClient.Countries {
				countries = append(countries, country)
			}

			return strings.Join(countries, ",")
		}(),
		"trusted_countries", func() string {
			if len(trustedCountries) > 0 {
				return strings.Join(trustedCountries, ",")
			}

			return "N/A"
		}(),
		"total_countries", len(remoteClient.Countries),
		"allowed_max_countries", allowedMaxCountries,
		"ips", func() string {
			var ips []string

			for ipAddress := range remoteClient.IPs {
				ips = append(ips, ipAddress)
			}

			return strings.Join(ips, ",")
		}(),
		"trusted_ips", func() string {
			if len(trustedIPs) > 0 {
				return strings.Join(trustedIPs, ",")
			}

			return "N/A"
		}(),
		"total_ips", len(remoteClient.IPs),
		"allowed_max_ips", allowedMaxIPs,
		"action", actionText)

	return fmt.Sprintf("action=%s", actionText)
}
