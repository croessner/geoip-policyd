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
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-kit/log/level"
	"github.com/oschwald/maxminddb-golang"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	geoIPLookupSpanName     = "geoip.lookup"
	geoIPMMDBLookupSpanName = "geoip.mmdb.lookup"
	geoIPProviderAttribute  = "geoip.provider"
	geoIPReaderCloseDelay   = time.Minute
	geoIPReloadInterval     = 300 * time.Second

	// geoIPSchemaProbeLimit bounds how many networks the loader decodes to prove the schema.
	geoIPSchemaProbeLimit = 1024

	// geoIPStaleDatabaseAge is the build age after which a loaded database triggers a warning.
	geoIPStaleDatabaseAge = 30 * 24 * time.Hour

	geoIPProviderAuto    = "auto"
	geoIPProviderMaxMind = "maxmind"
	geoIPProviderIPinfo  = "ipinfo"
)

// geoIPCountryRecord is a decoded MMDB record that exposes an ISO 3166-1 alpha-2 country code.
type geoIPCountryRecord interface {
	CountryCode() string
}

// geoIPRecordSchema describes how one GeoIP provider lays out its MMDB records.
// Implementations only provide decode targets; all reader access stays in geoIPDatabase and the loader.
type geoIPRecordSchema interface {
	// Provider returns the stable provider label used in logs and spans.
	Provider() string
	// NewRecord returns a fresh pointer target for one MMDB decode.
	NewRecord() geoIPCountryRecord
}

// maxMindCountryRecord maps the GeoLite2/GeoIP2 (and compatible DB-IP) country layout.
type maxMindCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// CountryCode returns the nested country.iso_code value.
func (r *maxMindCountryRecord) CountryCode() string {
	return r.Country.ISOCode
}

// maxMindSchema decodes MaxMind-style records with a nested country map.
type maxMindSchema struct{}

// Provider returns the MaxMind provider label.
func (maxMindSchema) Provider() string {
	return geoIPProviderMaxMind
}

// NewRecord returns an empty MaxMind country record.
func (maxMindSchema) NewRecord() geoIPCountryRecord {
	return &maxMindCountryRecord{}
}

// ipInfoLiteCountryRecord maps the flat IPinfo Lite layout, where "country" holds the country name.
type ipInfoLiteCountryRecord struct {
	Code string `maxminddb:"country_code"`
}

// CountryCode returns the flat country_code value.
func (r *ipInfoLiteCountryRecord) CountryCode() string {
	return r.Code
}

// ipInfoLiteSchema decodes IPinfo Lite records.
type ipInfoLiteSchema struct{}

// Provider returns the IPinfo provider label.
func (ipInfoLiteSchema) Provider() string {
	return geoIPProviderIPinfo
}

// NewRecord returns an empty IPinfo Lite country record.
func (ipInfoLiteSchema) NewRecord() geoIPCountryRecord {
	return &ipInfoLiteCountryRecord{}
}

// geoIPDatabase is an immutable pairing of an open reader, the schema that must decode its records,
// and the modification time of the file it was loaded from. It is published and replaced as one unit.
type geoIPDatabase struct {
	reader  *maxminddb.Reader
	schema  geoIPRecordSchema
	modTime time.Time
}

// lookupCountryCode decodes the record for ip; found reports whether the database contains the network.
func (d *geoIPDatabase) lookupCountryCode(ip net.IP) (code string, found bool, err error) {
	record := d.schema.NewRecord()

	_, found, err = d.reader.LookupNetwork(ip, record)

	return record.CountryCode(), found, err
}

// GeoIPDatabaseLoader opens MMDB files and binds them to a verified provider schema.
type GeoIPDatabaseLoader struct {
	path       string
	provider   string
	probeLimit int
}

// NewGeoIPDatabaseLoader creates a loader for path; provider is one of auto, maxmind or ipinfo.
func NewGeoIPDatabaseLoader(path, provider string) *GeoIPDatabaseLoader {
	return &GeoIPDatabaseLoader{path: path, provider: provider, probeLimit: geoIPSchemaProbeLimit}
}

// Path returns the database file path watched by this loader.
func (l *GeoIPDatabaseLoader) Path() string {
	return l.path
}

// Load opens the database file, resolves its schema and verifies that the schema decodes real country codes.
// It never returns a partially valid database: on any failure after opening, the new reader is closed.
func (l *GeoIPDatabaseLoader) Load() (*geoIPDatabase, error) {
	// Stat before Open: if the file is replaced in between, the recorded mtime is older than the opened
	// content and the next auto-reload tick loads it again. The reverse order could miss an update.
	fileInfo, err := os.Stat(l.path)
	if err != nil {
		return nil, err
	}

	reader, err := maxminddb.Open(l.path)
	if err != nil {
		return nil, err
	}

	schema, err := l.resolveSchema(reader.Metadata.DatabaseType)
	if err == nil {
		err = l.verifySchema(reader, schema)
	}

	if err != nil {
		_ = reader.Close()

		return nil, fmt.Errorf("%s: %w", l.path, err)
	}

	return &geoIPDatabase{reader: reader, schema: schema, modTime: fileInfo.ModTime()}, nil
}

// resolveSchema maps the configured provider, or the database_type metadata for auto, to a record schema.
func (l *GeoIPDatabaseLoader) resolveSchema(databaseType string) (geoIPRecordSchema, error) {
	switch l.provider {
	case geoIPProviderMaxMind:
		return maxMindSchema{}, nil
	case geoIPProviderIPinfo:
		return ipInfoLiteSchema{}, nil
	case geoIPProviderAuto:
		return detectGeoIPSchema(databaseType)
	default:
		return nil, fmt.Errorf("%w: %q", errGeoIPUnknownProvider, l.provider)
	}
}

// detectGeoIPSchema selects IPinfo Lite for its database types, rejects other IPinfo products whose
// "country" field has a different meaning, and treats everything else as MaxMind-compatible.
func detectGeoIPSchema(databaseType string) (geoIPRecordSchema, error) {
	normalized := strings.ToLower(databaseType)

	if strings.HasPrefix(normalized, geoIPProviderIPinfo) {
		if strings.Contains(normalized, "lite") {
			return ipInfoLiteSchema{}, nil
		}

		return nil, fmt.Errorf("%w: unsupported IPinfo database type %q, only IPinfo Lite is supported",
			errGeoIPSchemaMismatch, databaseType)
	}

	return maxMindSchema{}, nil
}

// verifySchema walks the first networks of the database and requires that the schema decodes them
// without error and yields at least one country code. Fixed probe addresses are avoided because test
// and regional databases may not contain them, and a missing field decodes silently to "".
func (l *GeoIPDatabaseLoader) verifySchema(reader *maxminddb.Reader, schema geoIPRecordSchema) error {
	networks := reader.Networks(maxminddb.SkipAliasedNetworks)

	for checked := 0; checked < l.probeLimit && networks.Next(); checked++ {
		record := schema.NewRecord()

		if _, err := networks.Network(record); err != nil {
			return fmt.Errorf("%w: %s records cannot be decoded: %w", errGeoIPSchemaMismatch, schema.Provider(), err)
		}

		if record.CountryCode() != "" {
			return nil
		}
	}

	if err := networks.Err(); err != nil {
		return err
	}

	return fmt.Errorf("%w: no %s country code found in database type %q",
		errGeoIPSchemaMismatch, schema.Provider(), reader.Metadata.DatabaseType)
}

// GeoIP owns the active GeoIP database, reloads it through its loader and swaps it atomically.
type GeoIP struct {
	database   atomic.Pointer[geoIPDatabase]
	loader     *GeoIPDatabaseLoader
	closeDelay time.Duration
}

// NewGeoIP creates a GeoIP service without an active database; call Initialize to load the first one.
func NewGeoIP(loader *GeoIPDatabaseLoader) *GeoIP {
	return &GeoIP{loader: loader, closeDelay: geoIPReaderCloseDelay}
}

// Initialize loads and publishes the first database at startup. It does not count as a reload in metrics.
func (g *GeoIP) Initialize(ctx context.Context) error {
	return g.loadAndPublish(ctx, false)
}

// Reload loads the database through the loader and publishes it. On failure the active database stays in
// service; the outcome is recorded as ok, error or schema_mismatch.
func (g *GeoIP) Reload(ctx context.Context) error {
	return g.loadAndPublish(ctx, true)
}

// loadAndPublish implements Initialize and Reload; observe controls whether the reload metric is recorded.
func (g *GeoIP) loadAndPublish(ctx context.Context, observe bool) error {
	if g == nil || g.loader == nil {
		return errGeoIPLoaderMissing
	}

	database, err := g.loader.Load()
	if err != nil {
		if observe {
			g.observeReload(ctx, reloadResultFor(err))
		}

		msg := "Unable to load GeoIP database"
		if g.database.Load() != nil {
			msg = "Unable to reload GeoIP database, keeping the active database"
		}

		_ = level.Error(logger).Log("msg", msg, "error", err.Error())

		return err
	}

	g.publish(database)

	if observe {
		g.observeReload(ctx, resultOK)
	}

	g.logLoaded(database)

	return nil
}

// reloadResultFor maps a load error to its reload metric result label.
func reloadResultFor(err error) string {
	if errors.Is(err, errGeoIPSchemaMismatch) {
		return resultSchemaMismatch
	}

	return resultError
}

// RunAutoReload checks the database file every interval and reloads it when its modification time differs
// from the active database. It returns when ctx is done.
func (g *GeoIP) RunAutoReload(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.reloadIfChanged(ctx)
		}
	}
}

// reloadIfChanged reloads when the file mtime differs from the active database. Because the active mtime only
// advances after a successful load, a failed reload is retried on every tick until it succeeds.
func (g *GeoIP) reloadIfChanged(ctx context.Context) {
	if g == nil || g.loader == nil {
		return
	}

	fileInfo, err := os.Stat(g.loader.Path())
	if err != nil {
		g.observeReload(ctx, resultStatError)

		_ = level.Error(logger).Log("msg", "Unable to get GeoIP database file info", "error", err.Error())

		return
	}

	if active := g.database.Load(); active != nil && active.modTime.Equal(fileInfo.ModTime()) {
		return
	}

	_ = level.Info(logger).Log("msg", "GeoIP database file has changed", "file", g.loader.Path())

	_ = g.Reload(ctx)
}

// publish swaps in database and closes the previous reader after the grace period.
func (g *GeoIP) publish(database *geoIPDatabase) {
	previous := g.database.Swap(database)
	if previous != nil {
		g.closeReaderAfterGrace(previous.reader)
	}
}

// observeReload records one reload outcome when observability is enabled.
func (g *GeoIP) observeReload(ctx context.Context, result string) {
	if obs := currentObservability(); obs != nil {
		obs.ObserveGeoIPReload(ctx, result)
	}
}

// logLoaded reports the loaded provider and metadata, and warns when the database build is stale.
func (g *GeoIP) logLoaded(database *geoIPDatabase) {
	metadata := database.reader.Metadata
	buildTime := time.Unix(int64(metadata.BuildEpoch), 0).UTC()

	_ = level.Info(logger).Log(
		"msg", "GeoIP database loaded",
		"file", g.loader.Path(),
		"provider", database.schema.Provider(),
		"database_type", metadata.DatabaseType,
		"build_time", buildTime.Format(time.RFC3339),
	)

	if age := time.Since(buildTime); age > geoIPStaleDatabaseAge {
		_ = level.Warn(logger).Log(
			"msg", "GeoIP database is outdated, update it regularly",
			"file", g.loader.Path(),
			"age_days", int(age.Hours()/24),
		)
	}
}

// LookupCountryCode returns the ISO country code for an IP address without taking a global lock.
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

		ctx, span = obs.StartSpan(ctx, geoIPLookupSpanName, attribute.String("geoip.operation", "lookup"))

		defer func() {
			duration := time.Since(start)

			span.SetAttributes(attribute.String(labelResult, result))
			span.End()
			obs.ObserveGeoIPLookup(ctx, result, duration)
		}()
	}

	var database *geoIPDatabase
	if g != nil {
		database = g.database.Load()
	}

	if database == nil {
		result = resultUnavailable

		_ = level.Error(logger).Log("error", "no GeoIP database file available")

		return ""
	}

	return database.resolveCountryCode(ctx, obs, ipAddress, &result)
}

// resolveCountryCode parses ipAddress, performs the traced lookup and updates the caller-owned result label.
func (d *geoIPDatabase) resolveCountryCode(ctx context.Context, obs *Observability, ipAddress string, result *string) string {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		*result = resultInvalid

		return ""
	}

	if obs != nil {
		trace.SpanFromContext(ctx).SetAttributes(d.providerAttribute())
	}

	countryCode, lookupResult, err := d.tracedLookup(ctx, obs, ip)
	if err != nil {
		if obs != nil {
			obs.RecordSpanError(trace.SpanFromContext(ctx), err)
		}

		_ = level.Error(logger).Log("error", err.Error())
	}

	*result = lookupResult

	return countryCode
}

// tracedLookup wraps the concrete reader lookup in a child span so traces can isolate database access time.
func (d *geoIPDatabase) tracedLookup(ctx context.Context, obs *Observability, ip net.IP) (string, string, error) {
	var span trace.Span
	if obs != nil {
		_, span = obs.StartSpan(ctx, geoIPMMDBLookupSpanName, attribute.String("geoip.operation", "mmdb_lookup"), d.providerAttribute())
	}

	countryCode, found, err := d.lookupCountryCode(ip)

	lookupResult := resultMiss

	switch {
	case err != nil:
		lookupResult = resultError
	case found && countryCode != "":
		lookupResult = resultHit
	}

	if obs != nil {
		span.SetAttributes(attribute.String(labelResult, lookupResult))

		if err != nil {
			obs.RecordSpanError(span, err)
		}

		span.End()
	}

	return countryCode, lookupResult, err
}

// providerAttribute returns the span attribute that identifies the database provider.
func (d *geoIPDatabase) providerAttribute() attribute.KeyValue {
	return attribute.String(geoIPProviderAttribute, d.schema.Provider())
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
