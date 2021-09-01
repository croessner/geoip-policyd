package main

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
	"log"
	"strings"
)

const deferText = "action=DEFER Service temporarily not available"
const rejectText = "action=REJECT Your account seems to be compromised. Please contact your support"

type Set []string

type RemoteClient struct {
	Ips       Set `redis:"ips"`       // All known IP addresses
	Countries Set `redis:"countries"` // All known country codes
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

func (t *Set) RedisScan(x interface{}) error {
	bs, ok := x.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", x)
	}
	runes := []rune(string(bs))
	newString := string(runes[1:len(runes)-1])
	*t = strings.Split(newString, " ")
	return nil
}

func getPolicyResponse() string {
	var (
		ok bool
		request string
		sender string
		clientIP  string
		remote    RemoteClient
		redisConn = redisPool.Get()
	)

	//goland:noinspection GoUnhandledErrorResult
	defer redisConn.Close()

	if request, ok = policyRequest["request"]; ok {
		if request == "smtpd_access_policy" {
			if sender, ok = policyRequest["sender"]; ok {
				if len(sender) > 0 {
					if clientIP, ok = policyRequest["client_address"]; ok {
						key := fmt.Sprintf("%s%s", redisPrefix, sender)

						// Check Redis for the current sender
						if value, err := redis.Values(redisConn.Do("HGETALL", key)); err != nil {
							log.Println("Error:", err)
							return deferText
						} else {
							if err := redis.ScanStruct(value, &remote); err != nil {
								log.Println("Error:", err)
								return deferText
							}
						}

						remote.addIPAddress(clientIP)

						// Check current IP address country code
						countryCode := getCountryCode(clientIP)
						if len(countryCode) == 0 {
							if cfg.verbose {
								log.Println("Debug: No country countryCode present for", clientIP)
							}
						} else {
							remote.addCountryCode(countryCode)

							if _, err := redisConn.Do("HMSET",
								redis.Args{}.Add(key).AddFlat(&remote)...); err != nil {
								log.Println("Error:", err)
								return deferText
							}
						}

						// For each request update the expiry
						if _, err := redisConn.Do("EXPIRE",
							redis.Args{}.Add(key).Add(redisTTL)...); err != nil {
							log.Println("Error:", err)
							return deferText
						}

						log.Printf("Info: sender=<%s>; countries=%s; ip_addresses=%s; " +
								   "#countries=%d/%d; #ip_addresses=%d/%d\n",
								   sender, remote.Countries, remote.Ips,
								   len(remote.Countries), maxCountries, len(remote.Ips), maxIps)

						if len(remote.Countries) >= maxCountries {
							return rejectText
						}

						if len(remote.Ips) >= maxIps {
							return rejectText
						}
					}
				}
			}
		}
	}

	return "action=DUNNO"
}
