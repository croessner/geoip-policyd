// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-kit/log/level"
	"github.com/oschwald/maxminddb-golang"
)

const geoIPReaderCloseDelay = time.Minute

// GeoIP owns the active MaxMind reader and swaps it atomically during reloads.
type GeoIP struct {
	reader     atomic.Pointer[maxminddb.Reader]
	closeDelay time.Duration
}

// NewGeoIP initializes a GeoIP holder with an active reader and the default close grace period.
func NewGeoIP(reader *maxminddb.Reader) *GeoIP {
	geoIP := &GeoIP{closeDelay: geoIPReaderCloseDelay}
	geoIP.reader.Store(reader)

	return geoIP
}

// LookupCountryCode returns the ISO country code for an IP address without taking a global reader lock.
func (g *GeoIP) LookupCountryCode(ipAddress string) string {
	var (
		err    error
		record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
	)

	if g == nil || g.reader.Load() == nil {
		level.Error(logger).Log("error", "no GeoIP database file available")

		return ""
	}

	if val := os.Getenv("GO_TESTING"); val == "" {
		ip := net.ParseIP(ipAddress)
		if ip != nil {
			reader := g.reader.Load()
			if reader == nil {
				return ""
			}

			err = reader.Lookup(ip, &record)
			if err != nil {
				level.Error(logger).Log("error", err.Error())
			}

			return record.Country.ISOCode
		}
	}

	return ""
}

// SwapReader publishes a replacement reader and closes the previous reader after a short grace period.
func (g *GeoIP) SwapReader(reader *maxminddb.Reader) {
	if g == nil {
		return
	}

	previous := g.reader.Swap(reader)
	g.closeReaderAfterGrace(previous)
}

// closeReaderAfterGrace delays closing the old mmap-backed reader so in-flight lock-free lookups can finish.
func (g *GeoIP) closeReaderAfterGrace(reader *maxminddb.Reader) {
	if reader == nil {
		return
	}

	go func() {
		time.Sleep(g.closeDelay)

		_ = reader.Close()
	}()
}

// getCountryCode returns the ISO code of the country associated with the given IP address.
func getCountryCode(ipAddress string) string {
	return geoIP.LookupCountryCode(ipAddress)
}
