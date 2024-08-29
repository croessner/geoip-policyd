package main

import (
	"net"
	"os"
	"reflect"
	"testing"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func TestIsTrustedIP(t *testing.T) {
	tests := []struct {
		name       string
		trustedIPs []string
		clientIP   string
		guid       string
		want       bool
	}{
		{
			name:       "Empty IPs",
			trustedIPs: []string{},
			clientIP:   "10.0.0.1",
			guid:       "test",
			want:       false,
		},
		{
			name:       "Trusted single IP",
			trustedIPs: []string{"10.0.0.1"},
			clientIP:   "10.0.0.1",
			guid:       "test",
			want:       true,
		},
		{
			name:       "Non-Trusted Single IP",
			trustedIPs: []string{"10.0.0.1"},
			clientIP:   "10.0.0.2",
			guid:       "test",
			want:       false,
		},
		{
			name:       "Multiple IPs",
			trustedIPs: []string{"10.0.0.1", "10.0.0.2"},
			clientIP:   "10.0.0.2",
			guid:       "test",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTrustedIP(tt.trustedIPs, tt.clientIP, tt.guid); got != tt.want {
				t.Errorf("isTrustedIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetworkContainsIP(t *testing.T) {
	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, level.AllowNone())

	tests := []struct {
		name           string
		trustedIPOrNet string
		ipAddress      string
		guid           string
		want           bool
	}{
		{
			name:           "Valid IPv4 in network",
			trustedIPOrNet: "192.168.1.0/24",
			ipAddress:      "192.168.1.1",
			guid:           "test",
			want:           true,
		},
		{
			name:           "IPv4 not in network",
			trustedIPOrNet: "192.168.1.0/24",
			ipAddress:      "192.168.2.1",
			guid:           "test",
			want:           false,
		},
		{
			name:           "Invalid IPv4 network range",
			trustedIPOrNet: "300.168.1.0/24",
			ipAddress:      "192.168.1.1",
			guid:           "test",
			want:           false,
		},
		{
			name:           "Invalid IPv4 address",
			trustedIPOrNet: "192.168.1.0/24",
			ipAddress:      "300.168.1.1",
			guid:           "test",
			want:           false,
		},
		{
			name:           "Valid IPv6 in network",
			trustedIPOrNet: "2001:db8::/32",
			ipAddress:      "2001:db8::1",
			guid:           "test",
			want:           true,
		},
		{
			name:           "IPv6 not in network",
			trustedIPOrNet: "2001:db8::/32",
			ipAddress:      "2001:db9::1",
			guid:           "test",
			want:           false,
		},
		{
			name:           "Invalid IPv6 network range",
			trustedIPOrNet: "2001:db8:::/32",
			ipAddress:      "2001:db8::1",
			guid:           "test",
			want:           false,
		},
		{
			name:           "Invalid IPv6 address",
			trustedIPOrNet: "2001:db8::/32",
			ipAddress:      "2001:dg8::1",
			guid:           "test",
			want:           false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipAddress := net.ParseIP(tt.ipAddress)
			if got := networkContainsIP(tt.trustedIPOrNet, ipAddress, tt.guid); got != tt.want {
				t.Errorf("networkContainsIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckIPsPolicy(t *testing.T) {
	config = &CmdLineConfig{BlockPermanent: true}

	tests := []struct {
		name                  string
		remoteClient          *RemoteClient
		trustedIPs            []string
		clientIP              string
		policyResponse        *PolicyResponse
		expectedPolicyRespone *PolicyResponse
		allowedMaxIPs         int
		allowedMaxHomeIPs     int
		guid                  string
		want                  bool
	}{
		{
			name:                  "No trusted IPs, within max IP limits",
			remoteClient:          &RemoteClient{IPs: TTLStringMap{"1.1.1.1": 0, "2.2.2.2": 0}},
			trustedIPs:            []string{},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxIPs:         10,
			allowedMaxHomeIPs:     10,
			guid:                  "test1",
			want:                  false,
		},
		{
			name:                  "Client IP not trusted, exceeds max IP limits",
			remoteClient:          &RemoteClient{IPs: TTLStringMap{"1.1.1.1": 0, "2.2.2.2": 0, "3.3.3.3": 0, "4.4.4.4": 0, "5.5.5.5": 0, "6.6.6.6": 0}},
			trustedIPs:            []string{},
			clientIP:              "7.7.7.7",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: true},
			allowedMaxIPs:         5,
			allowedMaxHomeIPs:     5,
			guid:                  "test2",
			want:                  true,
		},
		{
			name:                  "Client IP trusted, within max IP limits",
			remoteClient:          &RemoteClient{IPs: TTLStringMap{"1.1.1.1": 0, "2.2.2.2": 0}},
			trustedIPs:            []string{"1.1.1.1"},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxIPs:         10,
			allowedMaxHomeIPs:     10,
			guid:                  "test3",
			want:                  false,
		},
		{
			name: "Client IP trusted, exceeds max home IP limits",
			remoteClient: &RemoteClient{
				IPs: TTLStringMap{"1.1.1.1": 0, "2.2.2.2": 0},
				HomeCountries: &RedisHomeCountries{
					IPs: TTLStringMap{"3.3.3.3": 0, "4.4.4.4": 0},
				},
			},
			trustedIPs:            []string{"1.1.1.1"},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxIPs:         10,
			allowedMaxHomeIPs:     1,
			guid:                  "test4",
			want:                  false,
		},
		{
			name:                  "All IPs trusted, within max IP limits",
			remoteClient:          &RemoteClient{IPs: TTLStringMap{"1.1.1.1": 0, "2.2.2.2": 0, "3.3.3.3": 0}},
			trustedIPs:            []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxIPs:         10,
			allowedMaxHomeIPs:     10,
			guid:                  "test7",
			want:                  false,
		},
		{
			name:                  "All IPs trusted, exceeds max IP limits",
			remoteClient:          &RemoteClient{IPs: TTLStringMap{"1.1.1.1": 0, "2.2.2.2": 0, "3.3.3.3": 0}},
			trustedIPs:            []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxIPs:         2,
			allowedMaxHomeIPs:     2,
			guid:                  "test8",
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkIPsPolicy(tt.remoteClient, tt.trustedIPs, tt.clientIP, tt.policyResponse, tt.allowedMaxIPs, tt.allowedMaxHomeIPs, tt.guid)
			if got != tt.want {
				t.Errorf("checkIPsPolicy() = %v, want %v", got, tt.want)
			}

			if !reflect.DeepEqual(tt.policyResponse, tt.expectedPolicyRespone) {
				t.Errorf("checkIPsPolicy() policyResponse = %v, want %v", tt.policyResponse, tt.expectedPolicyRespone)
			}
		})
	}
}

func TestCheckCountryPolicy(t *testing.T) {
	config = &CmdLineConfig{BlockPermanent: true}
	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	logger = level.NewFilter(logger, level.AllowNone())

	tests := []struct {
		name                    string
		remoteClient            *RemoteClient
		trustedCountries        []string
		countryCode             string
		policyResponse          *PolicyResponse
		expectedPolicyRespone   *PolicyResponse
		allowedMaxCountries     int
		allowedMaxHomeCountries int
		guid                    string
		want                    bool
	}{
		{
			name:                    "Trusted Country",
			remoteClient:            &RemoteClient{},
			trustedCountries:        []string{"US"},
			countryCode:             "US",
			policyResponse:          &PolicyResponse{fired: false},
			expectedPolicyRespone:   &PolicyResponse{fired: false},
			allowedMaxCountries:     10,
			allowedMaxHomeCountries: 10,
			guid:                    "test_guid",
			want:                    false,
		},
		{
			name:                    "Untrusted Country",
			remoteClient:            &RemoteClient{},
			trustedCountries:        []string{"US"},
			countryCode:             "CA",
			policyResponse:          &PolicyResponse{fired: false},
			expectedPolicyRespone:   &PolicyResponse{fired: true},
			allowedMaxCountries:     10,
			allowedMaxHomeCountries: 10,
			guid:                    "test_guid",
			want:                    true,
		},
		{
			name: "Exceeding Max Home Countries",
			remoteClient: &RemoteClient{
				HomeCountries: &RedisHomeCountries{
					Countries: TTLStringMap{"US": 0, "CA": 0, "MX": 0},
				},
			},
			trustedCountries:        []string{},
			countryCode:             "US",
			policyResponse:          &PolicyResponse{fired: false},
			expectedPolicyRespone:   &PolicyResponse{fired: true},
			allowedMaxCountries:     10,
			allowedMaxHomeCountries: 2,
			guid:                    "test_guid",
			want:                    true,
		},
		{
			name:                    "Empty Countries",
			remoteClient:            &RemoteClient{},
			trustedCountries:        []string{},
			countryCode:             "US",
			policyResponse:          &PolicyResponse{fired: false},
			expectedPolicyRespone:   &PolicyResponse{fired: false},
			allowedMaxCountries:     10,
			allowedMaxHomeCountries: 10,
			guid:                    "test_guid",
			want:                    false,
		},
		{
			name:                    "All Countries Trusted",
			remoteClient:            &RemoteClient{},
			trustedCountries:        []string{"US", "CA", "MX", "JP", "DE"},
			countryCode:             "DE",
			policyResponse:          &PolicyResponse{fired: false},
			expectedPolicyRespone:   &PolicyResponse{fired: false},
			allowedMaxCountries:     10,
			allowedMaxHomeCountries: 10,
			guid:                    "test_guid",
			want:                    false,
		},
		{
			name:                    "Null Remote Client",
			remoteClient:            nil,
			trustedCountries:        []string{"US"},
			countryCode:             "US",
			policyResponse:          &PolicyResponse{fired: false},
			expectedPolicyRespone:   &PolicyResponse{fired: false},
			allowedMaxCountries:     10,
			allowedMaxHomeCountries: 10,
			guid:                    "test_guid",
			want:                    false,
		},
		{
			name:                    "Multiple Trusted Countries without Match",
			remoteClient:            &RemoteClient{},
			trustedCountries:        []string{"US", "CA", "MX"},
			countryCode:             "JP",
			policyResponse:          &PolicyResponse{fired: false},
			expectedPolicyRespone:   &PolicyResponse{fired: true},
			allowedMaxCountries:     10,
			allowedMaxHomeCountries: 10,
			guid:                    "test_guid",
			want:                    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkCountryPolicy(tt.remoteClient, tt.trustedCountries, tt.countryCode, tt.policyResponse, tt.allowedMaxCountries, tt.allowedMaxHomeCountries, tt.guid); got != tt.want {
				t.Errorf("checkCountryPolicy() = %v, want %v", got, tt.want)
			}

			if !reflect.DeepEqual(tt.policyResponse, tt.expectedPolicyRespone) {
				t.Errorf("checkCountryPolicy() did not update policyResponse correctly")
			}
		})
	}
}

func initializeIfNil(value any, defaultValue any) any {
	switch v := value.(type) {
	case *int:
		if v == nil {
			return defaultValue
		}
	case *[]string:
		if v == nil {
			return defaultValue
		}
	case *HomeCountries:
		if v == nil {
			return defaultValue
		}
	}

	return value
}

func TestApplyCustomSettings(t *testing.T) {
	tests := []struct {
		name                            string
		customSettings                  *CustomSettings
		sender                          string
		allowedMaxIPs                   *int
		allowedMaxCountries             *int
		trustedIPs                      *[]string
		trustedCountries                *[]string
		homeCountries                   *HomeCountries
		allowedMaxHomeIPs               *int
		allowedMaxHomeCountries         *int
		dataCustomSettings              []Account
		preDataAllowedMaxIPs            int
		preDataAllowedMaxCountries      int
		preDataAllowedMaxHomeIPs        int
		preDataAllowedMaxHomeCountries  int
		expectedAllowedMaxIPs           int
		expectedAllowedMaxCountries     int
		expectedAllowedMaxHomeIPs       int
		expectedAllowedMaxHomeCountries int
		expectedTrustedIPs              []string
		expectedTrustedCountries        []string
		expectedHomeCountries           *HomeCountries
	}{
		{
			name:                            "Nil Custom Settings",
			customSettings:                  nil,
			sender:                          "test@test.com",
			dataCustomSettings:              nil,
			preDataAllowedMaxIPs:            5,
			preDataAllowedMaxCountries:      5,
			preDataAllowedMaxHomeIPs:        5,
			preDataAllowedMaxHomeCountries:  5,
			expectedAllowedMaxIPs:           5,
			expectedAllowedMaxCountries:     5,
			expectedAllowedMaxHomeIPs:       5,
			expectedAllowedMaxHomeCountries: 5,
			expectedTrustedIPs:              []string{},
			expectedTrustedCountries:        []string{},
			expectedHomeCountries:           &HomeCountries{},
		},
		{
			name:                            "Empty Data in Custom Settings",
			customSettings:                  &CustomSettings{},
			sender:                          "test@test.com",
			dataCustomSettings:              []Account{},
			preDataAllowedMaxIPs:            10,
			preDataAllowedMaxCountries:      10,
			preDataAllowedMaxHomeIPs:        10,
			preDataAllowedMaxHomeCountries:  10,
			expectedAllowedMaxIPs:           10,
			expectedAllowedMaxCountries:     10,
			expectedAllowedMaxHomeIPs:       10,
			expectedAllowedMaxHomeCountries: 10,
			expectedTrustedIPs:              []string{},
			expectedTrustedCountries:        []string{},
			expectedHomeCountries:           &HomeCountries{},
		},
		{
			name:           "Change Allowed Max IPs",
			customSettings: &CustomSettings{},
			sender:         "test@test.com",
			dataCustomSettings: []Account{
				{
					Sender: "test@test.com",
					IPs:    12,
				},
			},
			preDataAllowedMaxIPs:            8,
			preDataAllowedMaxCountries:      8,
			preDataAllowedMaxHomeIPs:        8,
			preDataAllowedMaxHomeCountries:  8,
			expectedAllowedMaxIPs:           12,
			expectedAllowedMaxCountries:     8,
			expectedAllowedMaxHomeIPs:       8,
			expectedAllowedMaxHomeCountries: 8,
			expectedTrustedIPs:              []string{},
			expectedTrustedCountries:        []string{},
			expectedHomeCountries:           &HomeCountries{},
		},
		{
			name:           "Set Trusted IPs and Countries",
			customSettings: &CustomSettings{},
			sender:         "example@example.com",
			dataCustomSettings: []Account{
				{
					Sender:           "example@example.com",
					IPs:              10,
					TrustedIPs:       []string{"192.168.1.1", "192.168.1.2"},
					TrustedCountries: []string{"DE", "US"},
				},
			},
			preDataAllowedMaxIPs:            8,
			preDataAllowedMaxCountries:      8,
			preDataAllowedMaxHomeIPs:        8,
			preDataAllowedMaxHomeCountries:  8,
			expectedAllowedMaxIPs:           10,
			expectedAllowedMaxCountries:     8,
			expectedAllowedMaxHomeIPs:       8,
			expectedAllowedMaxHomeCountries: 8,
			expectedTrustedIPs:              []string{"192.168.1.1", "192.168.1.2"},
			expectedTrustedCountries:        []string{"DE", "US"},
			expectedHomeCountries:           &HomeCountries{},
		},
		{
			name:           "Override Existing Settings",
			customSettings: &CustomSettings{},
			sender:         "override@example.com",
			dataCustomSettings: []Account{
				{
					Sender:           "override@example.com",
					IPs:              15,
					TrustedIPs:       []string{"172.16.0.1"},
					TrustedCountries: []string{"FR"},
					HomeCountries: &HomeCountries{
						Codes: []string{"US"},
					},
				},
			},
			preDataAllowedMaxIPs:            15,
			preDataAllowedMaxCountries:      15,
			preDataAllowedMaxHomeIPs:        15,
			preDataAllowedMaxHomeCountries:  15,
			expectedAllowedMaxIPs:           15,
			expectedAllowedMaxCountries:     15,
			expectedAllowedMaxHomeIPs:       15,
			expectedAllowedMaxHomeCountries: 15,
			expectedTrustedIPs:              []string{"172.16.0.1"},
			expectedTrustedCountries:        []string{"FR"},
			expectedHomeCountries:           &HomeCountries{Codes: []string{"US"}},
		},
		{
			name:           "Multiple Entries in Custom Settings",
			customSettings: &CustomSettings{},
			sender:         "multi@example.com",
			dataCustomSettings: []Account{
				{
					Sender:           "multi@example.com",
					IPs:              20,
					TrustedIPs:       []string{"10.0.0.1", "10.0.0.2"},
					TrustedCountries: []string{"JP", "BR"},
				},
				{
					Sender:           "another@example.com",
					IPs:              25,
					TrustedIPs:       []string{"8.8.8.8"},
					TrustedCountries: []string{"IN"},
				},
			},
			preDataAllowedMaxIPs:            10,
			preDataAllowedMaxCountries:      10,
			preDataAllowedMaxHomeIPs:        10,
			preDataAllowedMaxHomeCountries:  10,
			expectedAllowedMaxIPs:           20,
			expectedAllowedMaxCountries:     10,
			expectedAllowedMaxHomeIPs:       10,
			expectedAllowedMaxHomeCountries: 10,
			expectedTrustedIPs:              []string{"10.0.0.1", "10.0.0.2"},
			expectedTrustedCountries:        []string{"JP", "BR"},
			expectedHomeCountries:           &HomeCountries{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.customSettings != nil {
				tt.customSettings.Data = tt.dataCustomSettings
			}

			tt.allowedMaxIPs = initializeIfNil(tt.allowedMaxIPs, new(int)).(*int)
			tt.allowedMaxCountries = initializeIfNil(tt.allowedMaxCountries, new(int)).(*int)
			tt.allowedMaxHomeCountries = initializeIfNil(tt.allowedMaxHomeCountries, new(int)).(*int)
			tt.allowedMaxHomeIPs = initializeIfNil(tt.allowedMaxHomeIPs, new(int)).(*int)

			tt.trustedIPs = initializeIfNil(tt.trustedIPs, &[]string{}).(*[]string)
			tt.trustedCountries = initializeIfNil(tt.trustedCountries, &[]string{}).(*[]string)
			tt.homeCountries = initializeIfNil(tt.homeCountries, &HomeCountries{}).(*HomeCountries)

			*tt.allowedMaxIPs = tt.preDataAllowedMaxIPs
			*tt.allowedMaxCountries = tt.preDataAllowedMaxCountries
			*tt.allowedMaxHomeIPs = tt.preDataAllowedMaxHomeIPs
			*tt.allowedMaxHomeCountries = tt.preDataAllowedMaxHomeCountries

			applyCustomSettings(tt.customSettings, tt.sender, tt.allowedMaxIPs, tt.allowedMaxCountries, tt.trustedIPs, tt.trustedCountries, &tt.homeCountries.Codes, tt.allowedMaxHomeIPs, tt.allowedMaxHomeCountries)

			if *tt.allowedMaxIPs != tt.expectedAllowedMaxIPs {
				t.Errorf("Expected Allowed Max IPs = %v, got = %v", tt.expectedAllowedMaxIPs, *tt.allowedMaxIPs)
			}

			if *tt.allowedMaxCountries != tt.expectedAllowedMaxCountries {
				t.Errorf("Expected Allowed Max Countries = %v, got = %v", tt.expectedAllowedMaxCountries, *tt.allowedMaxCountries)
			}

			if *tt.allowedMaxHomeIPs != tt.expectedAllowedMaxHomeIPs {
				t.Errorf("Expected Allowed Max Home IPs = %v, got = %v", tt.expectedAllowedMaxHomeIPs, *tt.allowedMaxHomeIPs)
			}

			if *tt.allowedMaxHomeCountries != tt.expectedAllowedMaxHomeCountries {
				t.Errorf("Expected Allowed Max Home Countries = %v, got = %v", tt.expectedAllowedMaxHomeCountries, *tt.allowedMaxHomeCountries)
			}

			if !reflect.DeepEqual(*tt.trustedIPs, tt.expectedTrustedIPs) {
				t.Errorf("Expected = %v, got = %v", tt.expectedTrustedIPs, *tt.trustedIPs)
			}

			if !reflect.DeepEqual(*tt.trustedCountries, tt.expectedTrustedCountries) {
				t.Errorf("Expected = %v, got = %v", tt.expectedTrustedCountries, *tt.trustedCountries)
			}

			if !reflect.DeepEqual(tt.homeCountries, tt.expectedHomeCountries) {
				t.Errorf("Expected = %v, got = %v", tt.expectedHomeCountries, *tt.homeCountries)
			}
		})
	}
}
