package main

import (
	"encoding/json"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"log"
)

const deferText = "DEFER Service temporarily not available"
const rejectText = "REJECT Your account seems to be compromised. Please contact your support"

type RemoteClient struct {
	Ips       []string `redis:"ips"`       // All known IP addresses
	Countries []string `redis:"countries"` // All known country codes
}

var policyRequest map[string]string

func (r *RemoteClient) addCountryCode(countryCode string) {
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

func (r *RemoteClient) addIPAddress(ip string) {
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

func getPolicyResponse() string {
	var (
		ok               bool
		request          string
		sender           string
		clientIP         string
		remote           RemoteClient
		redisConn        = redisPool.Get()
		usedMaxIps       = cfg.MaxIps
		usedMaxCountries = cfg.MaxCountries
		actionText       = "DUNNO"
	)

	//goland:noinspection GoUnhandledErrorResult
	defer redisConn.Close()

	if request, ok = policyRequest["request"]; ok {
		if request == "smtpd_access_policy" {
			if sender, ok = policyRequest["sender"]; ok {
				if len(sender) > 0 {
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

						remote.addIPAddress(clientIP)

						// Check current IP address country code
						countryCode := getCountryCode(clientIP)
						if len(countryCode) == 0 {
							if cfg.Verbose {
								log.Println("Debug: No country countryCode present for", clientIP)
							}
						} else {
							remote.addCountryCode(countryCode)
							redisValue, _ := json.Marshal(remote)
							if _, err := redisConn.Do("SET",
								redis.Args{}.Add(key).Add(redisValue)...); err != nil {
								log.Println("Error:", err)
								return fmt.Sprintf("action=%s", deferText)
							}
						}

						// For each request update the expiry timestamp
						if _, err := redisConn.Do("EXPIRE",
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

	log.Printf("Info: sender=<%s>; countries=%s; ip_addresses=%s; "+
		"#countries=%d/%d; #ip_addresses=%d/%d; action=%s\n",
		sender, remote.Countries, remote.Ips,
		len(remote.Countries), usedMaxCountries, len(remote.Ips), usedMaxIps, actionText)

	return fmt.Sprintf("action=%s", actionText)
}
