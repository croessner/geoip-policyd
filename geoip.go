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
	"net"
	"os"
	"sync"

	"github.com/go-kit/log/level"
	"github.com/oschwald/maxminddb-golang"
)

type GeoIP struct {
	Reader *maxminddb.Reader
	mu     sync.RWMutex
}

// getCountryCode returns the ISO code of the country associated with the given IP address.
// It retrieves the geoIP.Reader and acquires a read lock on it. It then calls the Lookup function
// on the geoIP.Reader to find the country associated with the IP address. If an error occurs,
// it logs the error. Finally, it releases the read lock and returns the ISO code of the country.
func getCountryCode(ipAddress string) string {
	var (
		err    error
		record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
	)

	if geoIP == nil {
		level.Error(logger).Log("error", "no GeoIP database file available")

		return ""
	}

	if val := os.Getenv("GO_TESTING"); val == "" {
		ip := net.ParseIP(ipAddress)
		if ip != nil {
			geoIP.mu.RLock()

			err = geoIP.Reader.Lookup(ip, &record)
			if err != nil {
				level.Error(logger).Log("error", err.Error())
			}

			geoIP.mu.RUnlock()

			return record.Country.ISOCode
		}
	}

	return ""
}
