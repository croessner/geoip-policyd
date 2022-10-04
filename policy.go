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

type RemoteClient struct {
	IPs       []string `redis:"ips"`       // All known IP addresses
	Countries []string `redis:"countries"` // All known country codes
	Actions   []string `redis:"actions"`   // All actions that may have run
}

func (r *RemoteClient) AddCountryCode(countryCode string) bool {
	updated := false

	if len(r.Countries) == 0 {
		r.Countries = append(r.Countries, countryCode)
		updated = true
	} else {
		haveCC := false

		for _, value := range r.Countries {
			if value == countryCode {
				haveCC = true
			}
		}

		if !haveCC {
			r.Countries = append(r.Countries, countryCode)
			updated = true
		}
	}

	return updated
}

func (r *RemoteClient) AddIPAddress(ipAddress string) bool {
	updated := false

	if len(r.IPs) == 0 {
		r.IPs = append(r.IPs, ipAddress)
		updated = true
	} else {
		haveIP := false

		for _, value := range r.IPs {
			if value == ipAddress {
				haveIP = true
			}
		}

		if !haveIP {
			r.IPs = append(r.IPs, ipAddress)
			updated = true
		}
	}

	return updated
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

						newCC := false
						newIP := remoteClient.AddIPAddress(clientIP)

						// Check current IP address country code
						countryCode := getCountryCode(clientIP)
						if countryCode == "" {
							level.Debug(logger).Log(
								"guid", guid, "msg", "No country code present", "client_address", clientIP)
						} else {
							newCC = remoteClient.AddCountryCode(countryCode)
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

						// Flag indicates, if the operator action was successful
						ranOperator := false

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
							}
						} else if len(remoteClient.Countries) > allowedMaxCountries {
							actionText = rejectText
							requireActions = true
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
							}
						} else if len(remoteClient.IPs) > allowedMaxIPs {
							actionText = rejectText
							requireActions = true
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
									ranOperator = true
								}
							}
						}

						// Only change client information, if there was a new IP, a new country code or an action was taken.
						if newIP || newCC || ranOperator {
							redisValue, err = json.Marshal(remoteClient)
							if err != nil {
								return fmt.Sprintf("action=%s", deferText)
							}

							if err = redisHandle.Set(ctx, key, redisValue, time.Duration(0)).Err(); err != nil {
								level.Error(logger).Log("guid", guid, "error", err.Error())

								return fmt.Sprintf("action=%s", deferText)
							}
						}

						// For each request update the expiry timestamp
						if config.BlockPermanent {
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
			return strings.Join(remoteClient.Countries, ",")
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
			return strings.Join(remoteClient.IPs, ",")
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
