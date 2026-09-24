package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/attribute"
)

const (
	maxMindFixture      = "testdata/GeoIP2-City-Test.mmdb"
	ipInfoLiteFixture   = "testdata/IPinfo-Lite-Test.mmdb"
	ipInfoLegacyFixture = "testdata/IPinfo-Legacy-Test.mmdb"
	asnOnlyFixture      = "testdata/GeoLite2-ASN-Test.mmdb"

	// fixtureGBAddress resolves to GB in every country fixture.
	fixtureGBAddress = "81.2.69.142"
	fixtureGBCode    = "GB"
	// fixtureSEAddress resolves to SE only in the IPinfo Lite fixture, on a network without ASN fields.
	fixtureSEAddress = "89.160.20.1"
	fixtureSECode    = "SE"
)

// TestGeoIPLookupCountryCodeHandlesMissingDatabase covers the lock-free holder's empty-database contract.
func TestGeoIPLookupCountryCodeHandlesMissingDatabase(t *testing.T) {
	setQuietPolicyTestLogger(t)

	geoIP := NewGeoIP(nil)
	if countryCode := geoIP.LookupCountryCode("192.0.2.1"); countryCode != "" {
		t.Fatalf("LookupCountryCode() = %q, want empty string", countryCode)
	}
}

// TestGeoIPDatabaseLoaderResolvesProviders verifies automatic and explicit schema selection per fixture.
func TestGeoIPDatabaseLoaderResolvesProviders(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		provider     string
		wantProvider string
		ip           string
		wantCode     string
	}{
		{"auto maxmind", maxMindFixture, geoIPProviderAuto, geoIPProviderMaxMind, fixtureGBAddress, fixtureGBCode},
		{"explicit maxmind", maxMindFixture, geoIPProviderMaxMind, geoIPProviderMaxMind, fixtureGBAddress, fixtureGBCode},
		{"auto ipinfo", ipInfoLiteFixture, geoIPProviderAuto, geoIPProviderIPinfo, fixtureGBAddress, fixtureGBCode},
		{"explicit ipinfo", ipInfoLiteFixture, geoIPProviderIPinfo, geoIPProviderIPinfo, fixtureGBAddress, fixtureGBCode},
		{"ipinfo without asn", ipInfoLiteFixture, geoIPProviderAuto, geoIPProviderIPinfo, fixtureSEAddress, fixtureSECode},
		{"ipinfo ipv6", ipInfoLiteFixture, geoIPProviderAuto, geoIPProviderIPinfo, "2001:db8:1::5", "DE"},
		{"ipinfo unknown network", ipInfoLiteFixture, geoIPProviderAuto, geoIPProviderIPinfo, "192.0.2.1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := loadGeoIPDatabaseForTest(t, tt.path, tt.provider)

			if got := database.schema.Provider(); got != tt.wantProvider {
				t.Fatalf("Provider() = %q, want %q", got, tt.wantProvider)
			}

			code, _, err := database.lookupCountryCode(parseIPForTest(t, tt.ip))
			if err != nil {
				t.Fatalf("lookupCountryCode() error = %v", err)
			}

			if code != tt.wantCode {
				t.Fatalf("lookupCountryCode(%s) = %q, want %q", tt.ip, code, tt.wantCode)
			}
		})
	}
}

// TestGeoIPDatabaseLoaderRejectsMismatchedDatabases verifies that wrong schemas fail loudly instead of yielding empty codes.
func TestGeoIPDatabaseLoaderRejectsMismatchedDatabases(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		provider string
	}{
		{"maxmind schema on ipinfo file", ipInfoLiteFixture, geoIPProviderMaxMind},
		{"ipinfo schema on maxmind file", maxMindFixture, geoIPProviderIPinfo},
		{"auto on legacy ipinfo file", ipInfoLegacyFixture, geoIPProviderAuto},
		{"ipinfo schema on legacy ipinfo file", ipInfoLegacyFixture, geoIPProviderIPinfo},
		{"auto on asn-only file", asnOnlyFixture, geoIPProviderAuto},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, err := NewGeoIPDatabaseLoader(tt.path, tt.provider).Load()
			if database != nil {
				_ = database.reader.Close()

				t.Fatalf("Load() returned a database for a mismatched file")
			}

			if !errors.Is(err, errGeoIPSchemaMismatch) {
				t.Fatalf("Load() error = %v, want %v", err, errGeoIPSchemaMismatch)
			}
		})
	}
}

// TestGeoIPDatabaseLoaderRejectsUnknownProvider verifies the loader's defensive provider check.
func TestGeoIPDatabaseLoaderRejectsUnknownProvider(t *testing.T) {
	_, err := NewGeoIPDatabaseLoader(maxMindFixture, "dbip").Load()
	if !errors.Is(err, errGeoIPUnknownProvider) {
		t.Fatalf("Load() error = %v, want %v", err, errGeoIPUnknownProvider)
	}
}

// TestGeoIPDatabaseLoaderRejectsMissingFile verifies that a missing path fails before any reader is opened.
func TestGeoIPDatabaseLoaderRejectsMissingFile(t *testing.T) {
	_, err := NewGeoIPDatabaseLoader(filepath.Join(t.TempDir(), "missing.mmdb"), geoIPProviderAuto).Load()
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() error = %v, want %v", err, os.ErrNotExist)
	}
}

// TestGeoIPReloadRecordsResultMetrics verifies the reload metric labels for startup, success and each failure class.
func TestGeoIPReloadRecordsResultMetrics(t *testing.T) {
	setQuietPolicyTestLogger(t)

	obs := installGeoIPMetricsTestRuntime(t)
	path := copyFixtureForTest(t, maxMindFixture)
	geoIP := newLoadedGeoIPForTest(t, path, geoIPProviderMaxMind)

	if got := reloadMetricForTest(obs, resultOK); got != 0 {
		t.Fatalf("reloads{ok} after Initialize() = %v, want 0", got)
	}

	if err := geoIP.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	copyFileForTest(t, ipInfoLiteFixture, path)

	if err := geoIP.Reload(context.Background()); !errors.Is(err, errGeoIPSchemaMismatch) {
		t.Fatalf("Reload() error = %v, want %v", err, errGeoIPSchemaMismatch)
	}

	writeFileAtomicallyForTest(t, path, []byte("corrupt"))

	if err := geoIP.Reload(context.Background()); err == nil {
		t.Fatal("Reload() error = nil, want error for a corrupt file")
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("os.Remove() error = %v", err)
	}

	geoIP.reloadIfChanged(context.Background())

	want := map[string]float64{resultOK: 1, resultSchemaMismatch: 1, resultError: 1, resultStatError: 1}
	for result, count := range want {
		if got := reloadMetricForTest(obs, result); got != count {
			t.Errorf("reloads{%s} = %v, want %v", result, got, count)
		}
	}
}

// TestGeoIPReloadKeepsActiveDatabaseOnFailure is the regression test for reloads that used to publish a nil reader.
func TestGeoIPReloadKeepsActiveDatabaseOnFailure(t *testing.T) {
	setQuietPolicyTestLogger(t)

	path := copyFixtureForTest(t, maxMindFixture)
	geoIP := newLoadedGeoIPForTest(t, path, geoIPProviderAuto)
	active := geoIP.database.Load()

	writeFileAtomicallyForTest(t, path, []byte("not an mmdb file"))

	if err := geoIP.Reload(context.Background()); err == nil {
		t.Fatal("Reload() error = nil, want error for a corrupt file")
	}

	if geoIP.database.Load() != active {
		t.Fatal("Reload() replaced the active database after a failure")
	}

	if code := geoIP.LookupCountryCode(fixtureGBAddress); code != fixtureGBCode {
		t.Fatalf("LookupCountryCode() after failed reload = %q, want GB", code)
	}
}

// TestGeoIPReloadSwitchesProvider verifies that reader and schema are published together.
func TestGeoIPReloadSwitchesProvider(t *testing.T) {
	setQuietPolicyTestLogger(t)

	path := copyFixtureForTest(t, maxMindFixture)
	geoIP := newLoadedGeoIPForTest(t, path, geoIPProviderAuto)

	copyFileForTest(t, ipInfoLiteFixture, path)

	if err := geoIP.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	if got := geoIP.database.Load().schema.Provider(); got != geoIPProviderIPinfo {
		t.Fatalf("Provider() = %q, want %q", got, geoIPProviderIPinfo)
	}

	if code := geoIP.LookupCountryCode(fixtureSEAddress); code != fixtureSECode {
		t.Fatalf("LookupCountryCode() = %q, want SE", code)
	}
}

// TestGeoIPReloadIfChangedRetriesAfterFailure verifies that a failed auto-reload is retried on the next tick.
func TestGeoIPReloadIfChangedRetriesAfterFailure(t *testing.T) {
	setQuietPolicyTestLogger(t)

	path := copyFixtureForTest(t, maxMindFixture)
	geoIP := newLoadedGeoIPForTest(t, path, geoIPProviderAuto)
	active := geoIP.database.Load()

	writeFileAtomicallyForTest(t, path, []byte("partial"))

	touchForTest(t, path, active.modTime.Add(time.Minute))
	geoIP.reloadIfChanged(context.Background())

	if geoIP.database.Load() != active {
		t.Fatal("reloadIfChanged() replaced the active database after a failure")
	}

	// The mtime stays unchanged from here on; only the retry can pick up the repaired file.
	copyFileForTest(t, ipInfoLiteFixture, path)
	touchForTest(t, path, active.modTime.Add(time.Minute))
	geoIP.reloadIfChanged(context.Background())

	if got := geoIP.database.Load().schema.Provider(); got != geoIPProviderIPinfo {
		t.Fatalf("Provider() after retry = %q, want %q", got, geoIPProviderIPinfo)
	}

	reloaded := geoIP.database.Load()
	geoIP.reloadIfChanged(context.Background())

	if geoIP.database.Load() != reloaded {
		t.Fatal("reloadIfChanged() reloaded an unchanged file")
	}
}

// TestGeoIPRunAutoReloadStopsOnContextCancel verifies that the reload loop honors cancellation.
func TestGeoIPRunAutoReloadStopsOnContextCancel(t *testing.T) {
	geoIP := NewGeoIP(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		geoIP.RunAutoReload(ctx, time.Hour)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunAutoReload() did not return after context cancellation")
	}
}

// TestGeoIPConcurrentLookupsDuringReload exercises lock-free lookups while databases are swapped; run with -race.
func TestGeoIPConcurrentLookupsDuringReload(t *testing.T) {
	setQuietPolicyTestLogger(t)

	path := copyFixtureForTest(t, maxMindFixture)
	geoIP := newLoadedGeoIPForTest(t, path, geoIPProviderAuto)
	// Lookups run concurrently with swaps, so replaced readers need a real grace period.
	geoIP.closeDelay = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var waitGroup sync.WaitGroup

	for range 4 {
		waitGroup.Go(func() {
			for ctx.Err() == nil {
				if code := geoIP.LookupCountryCode(fixtureGBAddress); code != fixtureGBCode {
					t.Errorf("LookupCountryCode() = %q, want GB", code)

					return
				}
			}
		})
	}

	sources := []string{ipInfoLiteFixture, maxMindFixture}
	for i := range 10 {
		copyFileForTest(t, sources[i%len(sources)], path)

		if err := geoIP.Reload(context.Background()); err != nil {
			t.Errorf("Reload() error = %v", err)
		}
	}

	cancel()
	waitGroup.Wait()
}

// TestGeoIPLookupCountryCodeCreatesMMDBChildSpan verifies that traces split wrapper time from database time.
func TestGeoIPLookupCountryCodeCreatesMMDBChildSpan(t *testing.T) {
	setQuietPolicyTestLogger(t)

	_, recorder := installGeoIPTraceTestRuntime(t)
	geoIP := newLoadedGeoIPForTest(t, ipInfoLiteFixture, geoIPProviderAuto)

	if countryCode := geoIP.LookupCountryCodeContext(context.Background(), fixtureGBAddress); countryCode != fixtureGBCode {
		t.Fatalf("LookupCountryCodeContext() = %q, want GB", countryCode)
	}

	lookupSpan, ok := recorder.findSpan(geoIPLookupSpanName)
	if !ok {
		t.Fatalf("span %q not recorded", geoIPLookupSpanName)
	}

	mmdbSpan, ok := recorder.findSpan(geoIPMMDBLookupSpanName)
	if !ok {
		t.Fatalf("span %q not recorded", geoIPMMDBLookupSpanName)
	}

	if mmdbSpan.traceID != lookupSpan.traceID {
		t.Fatalf("MMDB trace ID = %s, want %s", mmdbSpan.traceID, lookupSpan.traceID)
	}

	if mmdbSpan.parent.SpanID() != lookupSpan.spanID {
		t.Fatalf("MMDB parent span ID = %s, want %s", mmdbSpan.parent.SpanID(), lookupSpan.spanID)
	}

	wantProvider := attribute.String(geoIPProviderAttribute, geoIPProviderIPinfo)
	if !hasSpanAttribute(lookupSpan.attributes, wantProvider) || !hasSpanAttribute(mmdbSpan.attributes, wantProvider) {
		t.Fatalf("spans lack %s=%s", geoIPProviderAttribute, geoIPProviderIPinfo)
	}
}

// hasSpanAttribute reports whether attrs contains want with an equal value.
func hasSpanAttribute(attrs []attribute.KeyValue, want attribute.KeyValue) bool {
	for _, attr := range attrs {
		if attr.Key == want.Key && attr.Value == want.Value {
			return true
		}
	}

	return false
}

// loadGeoIPDatabaseForTest loads a fixture through the production loader and closes it after the test.
func loadGeoIPDatabaseForTest(t *testing.T, path, provider string) *geoIPDatabase {
	t.Helper()

	database, err := NewGeoIPDatabaseLoader(path, provider).Load()
	if err != nil {
		t.Fatalf("Load(%s, %s) error = %v", path, provider, err)
	}

	t.Cleanup(func() {
		_ = database.reader.Close()
	})

	return database
}

// newLoadedGeoIPForTest builds a GeoIP service with an initial database; replaced readers close immediately
// because these tests do not look up concurrently with swaps.
func newLoadedGeoIPForTest(t *testing.T, path, provider string) *GeoIP {
	t.Helper()

	geoIP := NewGeoIP(NewGeoIPDatabaseLoader(path, provider))
	geoIP.closeDelay = 0

	if err := geoIP.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	t.Cleanup(func() {
		if database := geoIP.database.Load(); database != nil {
			_ = database.reader.Close()
		}
	})

	return geoIP
}

// copyFixtureForTest copies a fixture into a per-test directory so tests can replace it safely.
func copyFixtureForTest(t *testing.T, source string) string {
	t.Helper()

	target := filepath.Join(t.TempDir(), "geoip.mmdb")
	copyFileForTest(t, source, target)

	return target
}

// copyFileForTest atomically replaces target with the contents of source, like an operator's mv-based update.
func copyFileForTest(t *testing.T, source, target string) {
	t.Helper()

	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("os.ReadFile(%s) error = %v", source, err)
	}

	writeFileAtomicallyForTest(t, target, data)
}

// writeFileAtomicallyForTest replaces target via rename so mmap-backed readers of the old inode stay valid.
func writeFileAtomicallyForTest(t *testing.T, target string, data []byte) {
	t.Helper()

	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%s) error = %v", tmp, err)
	}

	if err := os.Rename(tmp, target); err != nil {
		t.Fatalf("os.Rename(%s) error = %v", tmp, err)
	}
}

// touchForTest sets a deterministic modification time on path.
func touchForTest(t *testing.T, path string, modTime time.Time) {
	t.Helper()

	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("os.Chtimes(%s) error = %v", path, err)
	}
}

// installGeoIPMetricsTestRuntime installs a Prometheus-only observability runtime for GeoIP metric assertions.
func installGeoIPMetricsTestRuntime(t *testing.T) *Observability {
	t.Helper()

	obs, err := NewObservability(t.Context(), ObservabilityConfig{PrometheusEnabled: true}, "test-version", log.NewNopLogger())
	if err != nil {
		t.Fatalf("NewObservability() error = %v", err)
	}

	previousConfig := config
	config = &CmdLineConfig{observabilityRuntime: obs}

	t.Cleanup(func() {
		config = previousConfig
	})

	return obs
}

// reloadMetricForTest returns the current geoip_policyd_geoip_reloads_total value for result.
func reloadMetricForTest(obs *Observability, result string) float64 {
	return testutil.ToFloat64(obs.metrics.geoIPReloads.WithLabelValues(result))
}

// installGeoIPTraceTestRuntime installs an in-memory tracing runtime for GeoIP tests.
func installGeoIPTraceTestRuntime(t *testing.T) (*Observability, *spanRecorder) {
	t.Helper()

	obs, recorder := newTraceTestObservability(t)
	previousConfig := config
	config = &CmdLineConfig{observabilityRuntime: obs}

	t.Cleanup(func() {
		config = previousConfig
	})

	return obs, recorder
}

// parseIPForTest parses a literal test address or fails the test.
func parseIPForTest(t *testing.T, value string) net.IP {
	t.Helper()

	ip := net.ParseIP(value)
	if ip == nil {
		t.Fatalf("net.ParseIP(%q) = nil", value)
	}

	return ip
}
