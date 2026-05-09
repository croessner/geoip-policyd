package main

import (
	"os"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

const (
	testCountryAT      = "AT"
	testCountryDE      = "DE"
	testCountryFR      = "FR"
	testCountryUS      = "US"
	testExactIPv4      = "192.0.2.10"
	testIPv6Prefix     = "2001:db8::/32"
	testPolicyProtocol = "smtpd_access_policy"
	testPolicyIP       = "192.0.2.15"
	testPolicyUser     = "user@example.com"
	testRequestIPKey   = "client_address"
	testRequestKey     = "request"
	testSenderTarget   = "target@example.com"
	testTrustedCIDR    = "198.51.100.0/24"
	testTrustedHost    = "198.51.100.1"
	testTrustedHostAlt = "198.51.100.23"
)

// setQuietPolicyTestLogger installs a logger that keeps policy tests deterministic and silent.
func setQuietPolicyTestLogger(t *testing.T) {
	t.Helper()

	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, level.AllowNone())
}

func TestNewRedisCacheWritePlan(t *testing.T) {
	tests := []struct {
		name                  string
		config                *CmdLineConfig
		remoteClient          *RemoteClient
		expectedExpiration    time.Duration
		expectedImmediateDrop bool
	}{
		{
			name:               "unlocked client uses configured TTL",
			config:             &CmdLineConfig{RedisTTL: 3600},
			remoteClient:       &RemoteClient{},
			expectedExpiration: time.Hour,
		},
		{
			name:         "locked client persists via SET without expiration",
			config:       &CmdLineConfig{RedisTTL: 3600},
			remoteClient: &RemoteClient{Locked: true},
		},
		{
			name:                  "zero TTL preserves immediate-expire behavior",
			config:                &CmdLineConfig{RedisTTL: 0},
			remoteClient:          &RemoteClient{},
			expectedImmediateDrop: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := newRedisCacheWritePlan(tt.config, tt.remoteClient)
			if plan.expiration != tt.expectedExpiration {
				t.Fatalf("expiration = %s, want %s", plan.expiration, tt.expectedExpiration)
			}

			if plan.deleteImmediately != tt.expectedImmediateDrop {
				t.Fatalf("deleteImmediately = %v, want %v", plan.deleteImmediately, tt.expectedImmediateDrop)
			}
		})
	}
}

func TestNetworkMatcherContainsExactAndPrefix(t *testing.T) {
	setQuietPolicyTestLogger(t)

	config = &CmdLineConfig{}

	matcher := NewNetworkMatcher([]string{testExactIPv4, testIPv6Prefix, "invalid"})

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "exact IPv4", ip: testExactIPv4, want: true},
		{name: "IPv6 prefix", ip: "2001:db8::5", want: true},
		{name: "outside prefix", ip: "2001:db9::5", want: false},
		{name: "invalid client IP", ip: "not-an-ip", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.ContainsString(tt.ip, "test"); got != tt.want {
				t.Fatalf("ContainsString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCustomSettingsApplyToUsesCompiledAccount(t *testing.T) {
	setQuietPolicyTestLogger(t)

	config = &CmdLineConfig{}

	customSettings := &CustomSettings{Data: []Account{
		{
			Sender:           "other@example.com",
			IPs:              2,
			TrustedCountries: []string{testCountryFR},
		},
		{
			Sender:           testSenderTarget,
			IPs:              5,
			Countries:        4,
			TrustedIPs:       []string{testTrustedCIDR},
			TrustedCountries: []string{testCountryDE},
			HomeCountries: &HomeCountries{
				Codes:     []string{testCountryAT},
				IPs:       3,
				Countries: 2,
			},
		},
	}}
	customSettings.Compile()

	settings := NewPolicySettings(nil, nil, []string{testCountryUS}, 10, 10, 10, 10)
	customSettings.ApplyTo(testSenderTarget, settings)

	if settings.AllowedMaxForeignIPs != 5 {
		t.Fatalf("AllowedMaxForeignIPs = %d, want 5", settings.AllowedMaxForeignIPs)
	}

	if settings.AllowedMaxForeignCountries != 4 {
		t.Fatalf("AllowedMaxForeignCountries = %d, want 4", settings.AllowedMaxForeignCountries)
	}

	if settings.AllowedMaxHomeIPs != 3 {
		t.Fatalf("AllowedMaxHomeIPs = %d, want 3", settings.AllowedMaxHomeIPs)
	}

	if settings.AllowedMaxHomeCountries != 2 {
		t.Fatalf("AllowedMaxHomeCountries = %d, want 2", settings.AllowedMaxHomeCountries)
	}

	if !settings.trustedIPMatcher.ContainsString(testTrustedHostAlt, "test") {
		t.Fatal("compiled trusted IP matcher did not match account CIDR")
	}

	if !settings.trustedCountrySet.Contains(testCountryDE) {
		t.Fatal("compiled trusted country set did not match account country")
	}

	if !settings.homeCountrySet.Contains(testCountryAT) {
		t.Fatal("compiled home country set did not match account country")
	}
}

func TestCustomSettingsCloneSeparatesMutableAccountData(t *testing.T) {
	original := &CustomSettings{Data: []Account{
		{
			Sender:           testSenderTarget,
			TrustedIPs:       []string{testTrustedHost},
			TrustedCountries: []string{testCountryDE},
			HomeCountries: &HomeCountries{
				Codes: []string{testCountryAT},
			},
		},
	}}
	original.Compile()

	clone := original.Clone()
	clone.Data[0].TrustedIPs[0] = "203.0.113.1"
	clone.Data[0].TrustedCountries[0] = testCountryFR
	clone.Data[0].Codes[0] = testCountryUS

	if original.Data[0].TrustedIPs[0] != testTrustedHost {
		t.Fatalf("original trusted IP mutated to %q", original.Data[0].TrustedIPs[0])
	}

	if original.Data[0].TrustedCountries[0] != testCountryDE {
		t.Fatalf("original trusted country mutated to %q", original.Data[0].TrustedCountries[0])
	}

	if original.Data[0].Codes[0] != testCountryAT {
		t.Fatalf("original home country mutated to %q", original.Data[0].Codes[0])
	}

	if clone.compiled != nil {
		t.Fatal("clone should not carry compiled index from published settings")
	}
}

func TestPolicySettingsEvaluateUsesCompiledHomeCountry(t *testing.T) {
	setQuietPolicyTestLogger(t)

	config = &CmdLineConfig{BlockPermanent: true, RedisTTL: redisTTL}

	settings := NewPolicySettings(nil, nil, []string{testCountryDE}, 10, 1, 10, 10)
	remoteClient := &RemoteClient{}
	policyResponse := &PolicyResponse{}

	if settings.Evaluate(remoteClient, testCountryDE, policyResponse, testTrustedHost, "test") {
		t.Fatal("first home-country IP should not fire policy")
	}

	if !remoteClient.haveHomeIPs() || len(remoteClient.HomeCountries.IPs) != 1 {
		t.Fatalf("home IPs = %#v, want one entry", remoteClient.HomeCountries)
	}

	if !settings.Evaluate(remoteClient, testCountryDE, policyResponse, "198.51.100.2", "test") {
		t.Fatal("second home-country IP should fire with max-home-ips=1")
	}

	if !policyResponse.fired {
		t.Fatal("policyResponse.fired = false, want true")
	}

	if !remoteClient.Locked {
		t.Fatal("remoteClient.Locked = false, want true")
	}
}

func TestPolicySettingsEvaluateUsesCompiledTrustedIP(t *testing.T) {
	setQuietPolicyTestLogger(t)

	config = &CmdLineConfig{BlockPermanent: true}

	settings := NewPolicySettings([]string{testTrustedCIDR}, nil, nil, 1, 1, 10, 10)
	remoteClient := &RemoteClient{}
	policyResponse := &PolicyResponse{}

	if settings.Evaluate(remoteClient, testCountryUS, policyResponse, testTrustedHostAlt, "test") {
		t.Fatal("trusted IP should not fire policy")
	}

	if policyResponse.fired {
		t.Fatal("policyResponse.fired = true, want false")
	}

	if remoteClient.Locked {
		t.Fatal("remoteClient.Locked = true, want false")
	}

	if remoteClient.haveForeignIPs() {
		t.Fatalf("trusted IP should not be added to foreign IPs: %#v", remoteClient.ForeignIPs)
	}
}

func TestPolicyInputFromMapUsesConfiguredUserAttribute(t *testing.T) {
	config = &CmdLineConfig{UseSASLUsername: true}

	input, err := NewPolicyInputFromMap(map[string]string{
		testRequestKey:   testPolicyProtocol,
		testRequestIPKey: testPolicyIP,
		"sasl_username":  testPolicyUser,
	})
	if err != nil {
		t.Fatalf("NewPolicyInputFromMap() error = %v", err)
	}

	if input.Sender != testPolicyUser {
		t.Fatalf("Sender = %q, want %s", input.Sender, testPolicyUser)
	}

	if input.ClientIP != testPolicyIP {
		t.Fatalf("ClientIP = %q, want %s", input.ClientIP, testPolicyIP)
	}
}
