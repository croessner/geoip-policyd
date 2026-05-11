package main

import (
	"context"
	"os"
	"testing"

	"github.com/oschwald/maxminddb-golang"
)

// TestGeoIPLookupCountryCodeHandlesMissingReader covers the lock-free reader holder's nil-reader contract.
func TestGeoIPLookupCountryCodeHandlesMissingReader(t *testing.T) {
	setQuietPolicyTestLogger(t)

	geoIP := NewGeoIP(nil)
	if countryCode := geoIP.LookupCountryCode("192.0.2.1"); countryCode != "" {
		t.Fatalf("LookupCountryCode() = %q, want empty string", countryCode)
	}
}

// TestGeoIPSwapReaderClearsActiveReader verifies that reload failures can publish a nil reader safely.
func TestGeoIPSwapReaderClearsActiveReader(t *testing.T) {
	geoIP := NewGeoIP(nil)
	geoIP.SwapReader(nil)

	if reader := geoIP.reader.Load(); reader != nil {
		t.Fatalf("reader = %#v, want nil", reader)
	}
}

// TestGeoIPLookupCountryCodeCreatesMaxMindChildSpan verifies that traces split wrapper time from database time.
func TestGeoIPLookupCountryCodeCreatesMaxMindChildSpan(t *testing.T) {
	setQuietPolicyTestLogger(t)
	enableGeoIPLookupForTest(t)

	reader, err := maxminddb.Open("testdata/GeoIP2-City-Test.mmdb")
	if err != nil {
		t.Fatalf("maxminddb.Open() error = %v", err)
	}

	t.Cleanup(func() {
		_ = reader.Close()
	})

	_, recorder := installGeoIPTraceTestRuntime(t)
	geoIP := NewGeoIP(reader)

	if countryCode := geoIP.LookupCountryCodeContext(context.Background(), "81.2.69.142"); countryCode != "GB" {
		t.Fatalf("LookupCountryCodeContext() = %q, want GB", countryCode)
	}

	lookupSpan, ok := recorder.findSpan(geoIPLookupSpanName)
	if !ok {
		t.Fatalf("span %q not recorded", geoIPLookupSpanName)
	}

	maxMindSpan, ok := recorder.findSpan(geoIPMaxMindLookupSpanName)
	if !ok {
		t.Fatalf("span %q not recorded", geoIPMaxMindLookupSpanName)
	}

	if maxMindSpan.traceID != lookupSpan.traceID {
		t.Fatalf("MaxMind trace ID = %s, want %s", maxMindSpan.traceID, lookupSpan.traceID)
	}

	if maxMindSpan.parent.SpanID() != lookupSpan.spanID {
		t.Fatalf("MaxMind parent span ID = %s, want %s", maxMindSpan.parent.SpanID(), lookupSpan.spanID)
	}
}

// enableGeoIPLookupForTest clears the legacy test guard so fixture-backed lookups exercise MaxMind.
func enableGeoIPLookupForTest(t *testing.T) {
	t.Helper()

	previous, found := os.LookupEnv("GO_TESTING")

	if err := os.Unsetenv("GO_TESTING"); err != nil {
		t.Fatalf("os.Unsetenv(GO_TESTING) error = %v", err)
	}

	t.Cleanup(func() {
		if found {
			_ = os.Setenv("GO_TESTING", previous)
			return
		}

		_ = os.Unsetenv("GO_TESTING")
	})
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
