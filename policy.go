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
	"log"
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

	if request, ok = policyRequest["request"]; ok {
		if request == "smtpd_access_policy" {
			if sender, ok = policyRequest["sender"]; ok {
				if len(sender) > 0 {
					if cfg.UseLDAP {
						if ldapResult, err = ldapServer.Search(sender); err != nil {
							log.Println("Info:", err)
							if !strings.Contains(fmt.Sprint(err), "No Such Object") {
								if ldapServer.LDAPConn == nil {
									ldapServer.Connect()
									ldapServer.Bind()
									ldapResult, _ = ldapServer.Search(sender)
								}
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
							log.Println("Error:", err)
							return fmt.Sprintf("action=%s", deferText)
						} else {
							if reply != nil {
								if redisValue, err := redis.Bytes(reply, err); err != nil {
									log.Println("Error:", err)
									return fmt.Sprintf("action=%s", deferText)
								} else {
									if err := json.Unmarshal(redisValue, &remote); err != nil {
										log.Println("Error:", err)
									}
								}
							}
						}

						newCC := false
						newIP := remote.AddIPAddress(clientIP)

						// Check current IP address country code
						countryCode := getCountryCode(clientIP)
						if len(countryCode) == 0 {
							if cfg.Verbose == logLevelDebug {
								log.Println("Debug: No country code present for", clientIP)
							}
						} else {
							newCC = remote.AddCountryCode(countryCode)
						}

						if len(cs.Data) > 0 {
							for _, record := range cs.Data {
								if record.Sender == sender {
									if record.Ips > 0 {
										usedMaxIps = record.Ips
									}
									if record.Countries > 0 {
										usedMaxCountries = record.Countries
									}
									break // First match wins!
								}
							}
						}

						persist := false
						runActions := false

						// Flag indicates, if the operator action was successful
						ranOperator := false

						if len(remote.Countries) > usedMaxCountries {
							actionText = rejectText
							if cfg.BlockedNoExpire {
								persist = true
							}
							runActions = true
						}

						if len(remote.Ips) > usedMaxIps {
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
									log.Println("Error:", err)
								} else {
									if cfg.Verbose == logLevelDebug {
										log.Println("Debug: Action operator finished successfully")
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
								log.Println("Error:", err)
								return fmt.Sprintf("action=%s", deferText)
							}
						}

						// For each request update the expiry timestamp
						if persist {
							if _, err := redisConnW.Do("PERSIST",
								redis.Args{}.Add(key)...); err != nil {
								log.Println("Error:", err)
								return fmt.Sprintf("action=%s", deferText)
							}
						} else {
							if _, err := redisConnW.Do("EXPIRE",
								redis.Args{}.Add(key).Add(cfg.RedisTTL)...); err != nil {
								log.Println("Error:", err)
								return fmt.Sprintf("action=%s", deferText)
							}
						}
					}
				}
			}
		}
	}

	if cfg.Verbose >= logLevelInfo {
		log.Printf("Info: sender=<%s>; countries=%s; ip_addresses=%s; "+
			"#countries=%d/%d; #ip_addresses=%d/%d; action=%s\n",
			sender, remote.Countries, remote.Ips,
			len(remote.Countries), usedMaxCountries, len(remote.Ips), usedMaxIps, actionText)
	}

	return fmt.Sprintf("action=%s", actionText)
}
