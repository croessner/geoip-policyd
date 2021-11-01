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
	"fmt"
	"github.com/gomodule/redigo/redis"
	"net"
	"os"
	"strings"
)

const deferText = "DEFER Service temporarily not available"
const rejectText = "REJECT Your account seems to be compromised. Please contact your support"

type RemoteClient struct {
	Ips       []string `redis:"ips"`       // All known IP addresses
	Countries []string `redis:"countries"` // All known country codes
	Actions   []string `redis:"actions"`   // All actions that may have run
}

func (r *RemoteClient) AddCountryCode(countryCode string) bool {
	var updated = false
	if len(r.Countries) == 0 {
		r.Countries = append(r.Countries, countryCode)
		updated = true
	} else {
		var haveCC = false
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

func (r *RemoteClient) AddIPAddress(ip string) bool {
	var updated = false
	if len(r.Ips) == 0 {
		r.Ips = append(r.Ips, ip)
		updated = true
	} else {
		var haveIP = false
		for _, value := range r.Ips {
			if value == ip {
				haveIP = true
			}
		}
		if !haveIP {
			r.Ips = append(r.Ips, ip)
			updated = true
		}
	}
	return updated
}

func getPolicyResponse(cfg *CmdLineConfig, policyRequest map[string]string) string {
	var (
		ok               bool
		request          string
		sender           string
		clientIP         string
		ldapResult       string
		instance         string
		trustedCountries []string
		trustedIps       []string
		err              error
		remote           RemoteClient
		redisHelper      = &Redis{}
		usedMaxIps       = cfg.MaxIps
		usedMaxCountries = cfg.MaxCountries
		actionText       = "DUNNO"
		ldapServer       = &cfg.LDAP
	)

	redisConn := redisHelper.ReadConn()
	redisConnW := redisHelper.WriteConn()

	//goland:noinspection GoUnhandledErrorResult
	defer redisConn.Close()

	if val, ok := policyRequest["instance"]; ok {
		instance = val
	} else {
		instance = "-"
	}

	if request, ok = policyRequest["request"]; ok {
		if request == "smtpd_access_policy" {
			userAttribute := "sender"
			if cfg.UseSASLUsername {
				userAttribute = "sasl_username"
			}
			if sender, ok = policyRequest[userAttribute]; ok {
				if len(sender) > 0 {
					if cfg.UseLDAP {
						if ldapResult, err = ldapServer.search(sender, instance); err != nil {
							InfoLogger.Println(err)
							if !strings.Contains(fmt.Sprint(err), "No Such Object") {
								ldapServer.LDAPConn.Close()
								ldapServer.connect(instance)
								ldapServer.bind(instance)
								ldapResult, _ = ldapServer.search(sender, instance)
							}
						}
						if ldapResult != "" {
							sender = ldapResult
						}
					}
					if clientIP, ok = policyRequest["client_address"]; ok {
						key := fmt.Sprintf("%s%s", cfg.RedisPrefix, sender)

						// Check Redis for the current sender
						if reply, err := redisConn.Do("GET", key); err != nil {
							ErrorLogger.Println(err)
							return fmt.Sprintf("action=%s", deferText)
						} else {
							if reply != nil {
								if redisValue, err := redis.Bytes(reply, err); err != nil {
									ErrorLogger.Println(err)
									return fmt.Sprintf("action=%s", deferText)
								} else {
									if err := json.Unmarshal(redisValue, &remote); err != nil {
										ErrorLogger.Println(err)
									}
								}
							}
						}

						newCC := false
						newIP := remote.AddIPAddress(clientIP)

						// Check current IP address country code
						countryCode := getCountryCode(clientIP)
						if len(countryCode) == 0 {
							if cfg.VerboseLevel == logLevelDebug {
								DebugLogger.Printf("instance=\"%s\" No country code present for %s\n", instance, clientIP)
							}
						} else {
							newCC = remote.AddCountryCode(countryCode)
						}

						if val := os.Getenv("GO_TESTING"); val == "" {
							customSettings := cs.Load().(*CustomSettings)
							if customSettings != nil {
								if len(customSettings.Data) > 0 {
									for _, record := range customSettings.Data {
										if record.Sender == sender {
											if record.Ips > 0 {
												usedMaxIps = record.Ips
											}
											if record.Countries > 0 {
												usedMaxCountries = record.Countries
											}
											if len(record.TrustedCountries) > 0 {
												trustedCountries = record.TrustedCountries
											}
											if len(record.TrustedIps) > 0 {
												trustedIps = record.TrustedIps
											}
											break // First match wins!
										}
									}
								}
							}
						}

						persist := false
						runActions := false

						// Flag indicates, if the operator action was successful
						ranOperator := false

						if len(trustedCountries) > 0 {
							matchCountry := false
							for _, trustedCountry := range trustedCountries {
								if cfg.VerboseLevel == logLevelDebug {
									DebugLogger.Printf("instance=\"%s\" %s\n", instance, trustedCountry)
								}
								if trustedCountry == countryCode {
									if cfg.VerboseLevel == logLevelDebug {
										DebugLogger.Printf("instance=\"%s\" Country matched\n", instance)
									}
									matchCountry = true
									break
								}
							}
							if !matchCountry {
								actionText = rejectText
								if cfg.BlockedNoExpire {
									persist = true
								}
								runActions = true
							}
						} else if len(remote.Countries) > usedMaxCountries {
							actionText = rejectText
							if cfg.BlockedNoExpire {
								persist = true
							}
							runActions = true
						}

						if len(trustedIps) > 0 {
							matchIp := false
							ip := net.ParseIP(clientIP)
							for _, trustedIp := range trustedIps {
								_, network, err := net.ParseCIDR(trustedIp)
								if err != nil {
									ErrorLogger.Printf("%s is not a network, error: %s\n", network, err)
									continue
								}
								if cfg.VerboseLevel == logLevelDebug {
									DebugLogger.Printf("instance=\"%s\" Checking: %s -> %s\n", instance, ip.String(), network.String())
								}
								if network.Contains(ip) {
									if cfg.VerboseLevel == logLevelDebug {
										DebugLogger.Printf("instance=\"%s\" IP matched", instance)
									}
									matchIp = true
									break
								}
							}
							if !matchIp {
								actionText = rejectText
								if cfg.BlockedNoExpire {
									persist = true
								}
								runActions = true
							}
						} else if len(remote.Ips) > usedMaxIps {
							actionText = rejectText
							if cfg.BlockedNoExpire {
								persist = true
							}
							runActions = true
						}

						if cfg.RunActions && runActions {
							var a Action
							runOperator := true
							for _, action := range remote.Actions {
								if action == "operator" {
									runOperator = false
									break
								}
							}

							if cfg.RunActionOperator && runOperator {
								a = &EmailOperator{}
								if err := a.Call(sender, cfg); err != nil {
									ErrorLogger.Println(err)
								} else {
									if cfg.VerboseLevel == logLevelDebug {
										DebugLogger.Printf("instance=\"%s\" Action operator finished successfully\n", instance)
									}
									remote.Actions = append(remote.Actions, "operator")
									ranOperator = true
								}
							}
						}

						// Only change client information, if there was a new IP, a new country code or an action was taken.
						if newIP || newCC || ranOperator {
							redisValue, _ := json.Marshal(remote)
							if _, err := redisConnW.Do("SET",
								redis.Args{}.Add(key).Add(redisValue)...); err != nil {
								ErrorLogger.Println(err)
								return fmt.Sprintf("action=%s", deferText)
							}
						}

						// For each request update the expiry timestamp
						if persist {
							if _, err := redisConnW.Do("PERSIST",
								redis.Args{}.Add(key)...); err != nil {
								ErrorLogger.Println(err)
								return fmt.Sprintf("action=%s", deferText)
							}
						} else {
							if _, err := redisConnW.Do("EXPIRE",
								redis.Args{}.Add(key).Add(cfg.RedisTTL)...); err != nil {
								ErrorLogger.Println(err)
								return fmt.Sprintf("action=%s", deferText)
							}
						}
					}
				}
			}
		}
	}

	if cfg.UseSASLUsername {
		sender = fmt.Sprintf("sasl_username=\"%s\"", sender)
	} else {
		sender = fmt.Sprintf("sender=\"<%s>\"", sender)
	}

	if cfg.VerboseLevel >= logLevelInfo {
		InfoLogger.Printf("instance=\"%s\" %s countries=%s ip_addresses=%s #countries=%d/%d #ip_addresses=%d/%d action=\"%s\"\n",
			instance, sender, remote.Countries, remote.Ips,
			len(remote.Countries), usedMaxCountries, len(remote.Ips), usedMaxIps, actionText)
	}

	return fmt.Sprintf("action=%s", actionText)
}
