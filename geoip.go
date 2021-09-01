package main

import (
	"github.com/oschwald/maxminddb-golang"
	"log"
	"net"
)

var geoipReader *maxminddb.Reader

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
		err = geoipReader.Lookup(ip, &record)
		if err != nil {
			log.Panic("Panic: Critical error while looking up ISO code:", err)
		}
		return record.Country.ISOCode
	}
	return ""
}
