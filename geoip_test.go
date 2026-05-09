package main

import "testing"

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
