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
	"context"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-kit/log/level"
	"github.com/oschwald/maxminddb-golang"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const geoIPReaderCloseDelay = time.Minute

// GeoIP owns the active MaxMind reader and swaps it atomically during reloads.
type GeoIP struct {
	reader     atomic.Pointer[maxminddb.Reader]
	closeDelay time.Duration
}

// geoIPCountryRecord maps the MaxMind country response fields used by the policy engine.
type geoIPCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// NewGeoIP initializes a GeoIP holder with an active reader and the default close grace period.
func NewGeoIP(reader *maxminddb.Reader) *GeoIP {
	geoIP := &GeoIP{closeDelay: geoIPReaderCloseDelay}
	geoIP.reader.Store(reader)

	return geoIP
}

// LookupCountryCode returns the ISO country code for an IP address without taking a global reader lock.
func (g *GeoIP) LookupCountryCode(ipAddress string) string {
	return g.LookupCountryCodeContext(context.Background(), ipAddress)
}

// LookupCountryCodeContext returns the ISO country code while recording request-local telemetry.
func (g *GeoIP) LookupCountryCodeContext(ctx context.Context, ipAddress string) string {
	start := time.Now()
	result := resultMiss
	obs := currentObservability()

	if obs != nil {
		var span trace.Span

		ctx, span = obs.StartSpan(ctx, "geoip.lookup", attribute.String("geoip.operation", "lookup"))
		defer span.End()
		defer func() {
			obs.ObserveGeoIPLookup(ctx, result, time.Since(start))
		}()
	}

	if g == nil || g.reader.Load() == nil {
		result = resultUnavailable

		_ = level.Error(logger).Log("error", "no GeoIP database file available")

		return ""
	}

	if val := os.Getenv("GO_TESTING"); val == "" {
		return g.lookupCountryCode(ctx, obs, ipAddress, &result)
	}

	return ""
}

// lookupCountryCode performs the MaxMind lookup and updates the caller-owned result label.
func (g *GeoIP) lookupCountryCode(ctx context.Context, obs *Observability, ipAddress string, result *string) string {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		*result = resultInvalid

		return ""
	}

	reader := g.reader.Load()
	if reader == nil {
		*result = resultUnavailable

		return ""
	}

	record := &geoIPCountryRecord{}
	if err := reader.Lookup(ip, record); err != nil {
		*result = resultError

		if obs != nil {
			obs.RecordSpanError(trace.SpanFromContext(ctx), err)
		}

		_ = level.Error(logger).Log("error", err.Error())
	}

	if record.Country.ISOCode != "" {
		*result = resultHit
	}

	return record.Country.ISOCode
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

// getCountryCodeWithContext returns the ISO code with request context propagation.
func getCountryCodeWithContext(ctx context.Context, ipAddress string) string {
	return geoIP.LookupCountryCodeContext(ctx, ipAddress)
}
