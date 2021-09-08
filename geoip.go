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
	"github.com/oschwald/maxminddb-golang"
	"log"
	"net"
	"sync"
)

type GeoIP struct {
	Mu     sync.Mutex
	Reader *maxminddb.Reader
}

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
