package main

import (
	"github.com/oschwald/maxminddb-golang"
	"log"
	"net"
	"sync"
)

type GeoIP struct {
	Mu     sync.Mutex
	Reader *maxminddb.Reader
}

var geoip GeoIP

//goland:noinspection GoUnhandledErrorResult
func getCountryCode(s string) string {
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	var err error

	ip := net.ParseIP(s)
	if ip != nil {
		err = geoip.Reader.Lookup(ip, &record)
		if err != nil {
			log.Panic("Panic: Critical error while looking up ISO code:", err)
		}
		return record.Country.ISOCode
	}
	return ""
}
