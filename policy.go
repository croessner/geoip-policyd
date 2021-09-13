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
}

func (r *RemoteClient) AddCountryCode(countryCode string) {
	if len(r.Countries) == 0 {
		r.Countries = append(r.Countries, countryCode)
	} else {
		var haveCC = false
		for _, value := range r.Countries {
			if value == countryCode {
				haveCC = true
			}
		}
		if !haveCC {
			r.Countries = append(r.Countries, countryCode)
		}
	}
}

func (r *RemoteClient) AddIPAddress(ip string) {
	if len(r.Ips) == 0 {
		r.Ips = append(r.Ips, ip)
	} else {
		var haveIP = false
		for _, value := range r.Ips {
			if value == ip {
				haveIP = true
			}
		}
		if !haveIP {
			r.Ips = append(r.Ips, ip)
		}
	}
}

func getPolicyResponse(cfg *CmdLineConfig, policyRequest map[string]string) string {
	var (
		ok         bool
		request    string
		sender     string
		clientIP   string
		ldapResult string
		err        error
		remote     RemoteClient
		redisConn  = newRedisPool(
			cfg.RedisAddress,
			cfg.RedisPort,
			cfg.RedisDB,
			cfg.RedisUsername,
			cfg.RedisPassword,
		).Get()
		redisConnW       redis.Conn
		usedMaxIps       = cfg.MaxIps
		usedMaxCountries = cfg.MaxCountries
		actionText       = "DUNNO"
		ldapServer       = &cfg.LDAP
	)

	if !(cfg.RedisAddress == cfg.RedisAddressW && cfg.RedisPort == cfg.RedisPortW) {
		redisConnW = newRedisPool(
			cfg.RedisAddressW,
			cfg.RedisPortW,
			cfg.RedisDBW,
			cfg.RedisUsernameW,
			cfg.RedisPasswordW,
		).Get()
		if cfg.Verbose == logLevelDebug {
			log.Printf("Debug: Redis read server: %s:%d\n", cfg.RedisAddress, cfg.RedisPort)
			log.Printf("Debug: Redis write server: %s:%d\n", cfg.RedisAddressW, cfg.RedisPortW)
		}
		//goland:noinspection GoUnhandledErrorResult
		defer redisConnW.Close()
	} else {
		redisConnW = redisConn
		if cfg.Verbose == logLevelDebug {
			log.Printf("Debug: Redis read and write server: %s:%d\n", cfg.RedisAddress, cfg.RedisPort)
		}
	}

	//goland:noinspection GoUnhandledErrorResult
	defer redisConn.Close()

	if request, ok = policyRequest["request"]; ok {
		if request == "smtpd_access_policy" {
			if sender, ok = policyRequest["sender"]; ok {
				if len(sender) > 0 {
					if ldapResult, err = ldapServer.Search(sender); err != nil {
						log.Println("Info:", err)
						if !strings.Contains(fmt.Sprint(err), "No Such Object") {
							ldapServer.Mu.Lock()
							if ldapServer.LDAPConn == nil {
								ldapServer.Connect()
								ldapServer.Bind()
							}
							ldapServer.Mu.Unlock()
							ldapResult, _ = ldapServer.Search(sender)
						}
					}
					if ldapResult != "" {
						sender = ldapResult
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

						remote.AddIPAddress(clientIP)

						// Check current IP address country code
						countryCode := getCountryCode(clientIP)
						if len(countryCode) == 0 {
							if cfg.Verbose == logLevelDebug {
								log.Println("Debug: No country code present for", clientIP)
							}
						} else {
							remote.AddCountryCode(countryCode)
							redisValue, _ := json.Marshal(remote)
							if _, err := redisConnW.Do("SET",
								redis.Args{}.Add(key).Add(redisValue)...); err != nil {
								log.Println("Error:", err)
								return fmt.Sprintf("action=%s", deferText)
							}
						}

						// For each request update the expiry timestamp
						if _, err := redisConnW.Do("EXPIRE",
							redis.Args{}.Add(key).Add(cfg.RedisTTL)...); err != nil {
							log.Println("Error:", err)
							return fmt.Sprintf("action=%s", deferText)
						}

						if len(cfg.WhiteList.Data) > 0 {
							for _, record := range cfg.WhiteList.Data {
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

						if len(remote.Countries) > usedMaxCountries {
							actionText = rejectText
						}

						if len(remote.Ips) > usedMaxIps {
							actionText = rejectText
						}
					}
				}
			}
		}
	}

	if cfg.Verbose == logLevelInfo {
		log.Printf("Info: sender=<%s>; countries=%s; ip_addresses=%s; "+
			"#countries=%d/%d; #ip_addresses=%d/%d; action=%s\n",
			sender, remote.Countries, remote.Ips,
			len(remote.Countries), usedMaxCountries, len(remote.Ips), usedMaxIps, actionText)
	}

	return fmt.Sprintf("action=%s", actionText)
}
