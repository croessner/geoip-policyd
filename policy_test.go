package main

import (
	"net"
	"os"
	"reflect"
	"testing"
	"time"

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

// setTTL returns the Unix timestamp in nanoseconds for the current time plus one hour.
func setTTL() int64 {
	return time.Now().UnixNano() + time.Hour.Nanoseconds()
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
		allowedMaxForeignIPs  int
		allowedMaxHomeIPs     int
		guid                  string
		want                  bool
	}{
		{
			name:                  "No trusted IPs, within max IP limits",
			remoteClient:          &RemoteClient{ForeignIPs: TTLStringMap{"1.1.1.1": setTTL(), "2.2.2.2": setTTL()}},
			trustedIPs:            []string{},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxForeignIPs:  10,
			allowedMaxHomeIPs:     10,
			guid:                  "test1",
			want:                  false,
		},
		{
			name:                  "Client IP not trusted, exceeds max IP limits",
			remoteClient:          &RemoteClient{ForeignIPs: TTLStringMap{"1.1.1.1": setTTL(), "2.2.2.2": setTTL(), "3.3.3.3": setTTL(), "4.4.4.4": setTTL(), "5.5.5.5": setTTL(), "6.6.6.6": setTTL()}},
			trustedIPs:            []string{},
			clientIP:              "7.7.7.7",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: true},
			allowedMaxForeignIPs:  5,
			allowedMaxHomeIPs:     5,
			guid:                  "test2",
			want:                  true,
		},
		{
			name:                  "Client IP trusted, within max IP limits",
			remoteClient:          &RemoteClient{ForeignIPs: TTLStringMap{"1.1.1.1": setTTL(), "2.2.2.2": setTTL()}},
			trustedIPs:            []string{"1.1.1.1"},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxForeignIPs:  10,
			allowedMaxHomeIPs:     10,
			guid:                  "test3",
			want:                  false,
		},
		{
			name: "Client IP trusted, exceeds max home IP limits",
			remoteClient: &RemoteClient{
				ForeignIPs: TTLStringMap{"1.1.1.1": setTTL(), "2.2.2.2": setTTL()},
				HomeCountries: &RedisHomeCountries{
					IPs: TTLStringMap{"3.3.3.3": setTTL(), "4.4.4.4": setTTL()},
				},
			},
			trustedIPs:            []string{"1.1.1.1"},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxForeignIPs:  10,
			allowedMaxHomeIPs:     1,
			guid:                  "test4",
			want:                  false,
		},
		{
			name:                  "All IPs trusted, within max IP limits",
			remoteClient:          &RemoteClient{ForeignIPs: TTLStringMap{"1.1.1.1": setTTL(), "2.2.2.2": setTTL(), "3.3.3.3": setTTL()}},
			trustedIPs:            []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxForeignIPs:  10,
			allowedMaxHomeIPs:     10,
			guid:                  "test7",
			want:                  false,
		},
		{
			name:                  "All IPs trusted, exceeds max IP limits",
			remoteClient:          &RemoteClient{ForeignIPs: TTLStringMap{"1.1.1.1": setTTL(), "2.2.2.2": setTTL(), "3.3.3.3": setTTL()}},
			trustedIPs:            []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
			clientIP:              "1.1.1.1",
			policyResponse:        &PolicyResponse{fired: false},
			expectedPolicyRespone: &PolicyResponse{fired: false},
			allowedMaxForeignIPs:  2,
			allowedMaxHomeIPs:     2,
			guid:                  "test8",
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkIPsPolicy(tt.remoteClient, tt.trustedIPs, tt.clientIP, tt.policyResponse, tt.allowedMaxForeignIPs, tt.allowedMaxHomeIPs, tt.guid, false)
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
		name                       string
		remoteClient               *RemoteClient
		trustedCountries           []string
		countryCode                string
		policyResponse             *PolicyResponse
		expectedPolicyRespone      *PolicyResponse
		allowedMaxForeignCountries int
		allowedMaxHomeCountries    int
		guid                       string
		want                       bool
		isHome                     bool
	}{
		{
			name:                       "Trusted Country",
			remoteClient:               &RemoteClient{},
			trustedCountries:           []string{"US"},
			countryCode:                "US",
			policyResponse:             &PolicyResponse{fired: false},
			expectedPolicyRespone:      &PolicyResponse{fired: false},
			allowedMaxForeignCountries: 10,
			allowedMaxHomeCountries:    10,
			guid:                       "test_guid",
			want:                       false,
		},
		{
			name:                       "Untrusted Country",
			remoteClient:               &RemoteClient{},
			trustedCountries:           []string{"US"},
			countryCode:                "CA",
			policyResponse:             &PolicyResponse{fired: false},
			expectedPolicyRespone:      &PolicyResponse{fired: true},
			allowedMaxForeignCountries: 10,
			allowedMaxHomeCountries:    10,
			guid:                       "test_guid",
			want:                       true,
		},
		{
			name: "Exceeding Max Home Countries",
			remoteClient: &RemoteClient{
				HomeCountries: &RedisHomeCountries{
					Countries: TTLStringMap{"US": 0, "CA": 0, "MX": 0},
				},
			},
			trustedCountries:           []string{},
			countryCode:                "US",
			policyResponse:             &PolicyResponse{fired: false},
			expectedPolicyRespone:      &PolicyResponse{fired: true},
			allowedMaxForeignCountries: 10,
			allowedMaxHomeCountries:    2,
			guid:                       "test_guid",
			want:                       true,
			isHome:                     true,
		},
		{
			name:                       "Empty Countries",
			remoteClient:               &RemoteClient{},
			trustedCountries:           []string{},
			countryCode:                "US",
			policyResponse:             &PolicyResponse{fired: false},
			expectedPolicyRespone:      &PolicyResponse{fired: false},
			allowedMaxForeignCountries: 10,
			allowedMaxHomeCountries:    10,
			guid:                       "test_guid",
			want:                       false,
		},
		{
			name:                       "All Countries Trusted",
			remoteClient:               &RemoteClient{},
			trustedCountries:           []string{"US", "CA", "MX", "JP", "DE"},
			countryCode:                "DE",
			policyResponse:             &PolicyResponse{fired: false},
			expectedPolicyRespone:      &PolicyResponse{fired: false},
			allowedMaxForeignCountries: 10,
			allowedMaxHomeCountries:    10,
			guid:                       "test_guid",
			want:                       false,
		},
		{
			name:                       "Null Remote Client",
			remoteClient:               nil,
			trustedCountries:           []string{"US"},
			countryCode:                "US",
			policyResponse:             &PolicyResponse{fired: false},
			expectedPolicyRespone:      &PolicyResponse{fired: false},
			allowedMaxForeignCountries: 10,
			allowedMaxHomeCountries:    10,
			guid:                       "test_guid",
			want:                       false,
		},
		{
			name:                       "Multiple Trusted ForeignCountries without Match",
			remoteClient:               &RemoteClient{},
			trustedCountries:           []string{"US", "CA", "MX"},
			countryCode:                "JP",
			policyResponse:             &PolicyResponse{fired: false},
			expectedPolicyRespone:      &PolicyResponse{fired: true},
			allowedMaxForeignCountries: 10,
			allowedMaxHomeCountries:    10,
			guid:                       "test_guid",
			want:                       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkCountryPolicy(tt.remoteClient, tt.trustedCountries, tt.countryCode, tt.policyResponse, tt.allowedMaxForeignCountries, tt.allowedMaxHomeCountries, tt.guid, tt.isHome); got != tt.want {
				t.Errorf("checkCountryPolicy() = %v, want %v", got, tt.want)
			}

			if !reflect.DeepEqual(tt.policyResponse, tt.expectedPolicyRespone) {
				t.Errorf("checkCountryPolicy() did not update policyResponse correctly")
			}
		})
	}
}

// initializeIfNil initializes the value with the defaultValue if it is nil. It supports
// initializing pointers to int, slices of strings, and the HomeCountries struct.
// If the value is not nil, it is returned unchanged.
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
		name                               string
		customSettings                     *CustomSettings
		sender                             string
		allowedMaxForeignIPs               *int
		allowedMaxForeignCountries         *int
		trustedIPs                         *[]string
		trustedCountries                   *[]string
		homeCountries                      *HomeCountries
		allowedMaxHomeIPs                  *int
		allowedMaxHomeCountries            *int
		dataCustomSettings                 []Account
		preDataallowedMaxForeignIPs        int
		preDataallowedMaxForeignCountries  int
		preDataAllowedMaxHomeIPs           int
		preDataAllowedMaxHomeCountries     int
		expectedallowedMaxForeignIPs       int
		expectedallowedMaxForeignCountries int
		expectedAllowedMaxHomeIPs          int
		expectedAllowedMaxHomeCountries    int
		expectedTrustedIPs                 []string
		expectedTrustedCountries           []string
		expectedHomeCountries              *HomeCountries
	}{
		{
			name:                               "Nil Custom Settings",
			customSettings:                     nil,
			sender:                             "test@test.com",
			dataCustomSettings:                 nil,
			preDataallowedMaxForeignIPs:        5,
			preDataallowedMaxForeignCountries:  5,
			preDataAllowedMaxHomeIPs:           5,
			preDataAllowedMaxHomeCountries:     5,
			expectedallowedMaxForeignIPs:       5,
			expectedallowedMaxForeignCountries: 5,
			expectedAllowedMaxHomeIPs:          5,
			expectedAllowedMaxHomeCountries:    5,
			expectedTrustedIPs:                 []string{},
			expectedTrustedCountries:           []string{},
			expectedHomeCountries:              &HomeCountries{},
		},
		{
			name:                               "Empty Data in Custom Settings",
			customSettings:                     &CustomSettings{},
			sender:                             "test@test.com",
			dataCustomSettings:                 []Account{},
			preDataallowedMaxForeignIPs:        10,
			preDataallowedMaxForeignCountries:  10,
			preDataAllowedMaxHomeIPs:           10,
			preDataAllowedMaxHomeCountries:     10,
			expectedallowedMaxForeignIPs:       10,
			expectedallowedMaxForeignCountries: 10,
			expectedAllowedMaxHomeIPs:          10,
			expectedAllowedMaxHomeCountries:    10,
			expectedTrustedIPs:                 []string{},
			expectedTrustedCountries:           []string{},
			expectedHomeCountries:              &HomeCountries{},
		},
		{
			name:           "Change Allowed Max ForeignIPs",
			customSettings: &CustomSettings{},
			sender:         "test@test.com",
			dataCustomSettings: []Account{
				{
					Sender: "test@test.com",
					IPs:    12,
				},
			},
			preDataallowedMaxForeignIPs:        8,
			preDataallowedMaxForeignCountries:  8,
			preDataAllowedMaxHomeIPs:           8,
			preDataAllowedMaxHomeCountries:     8,
			expectedallowedMaxForeignIPs:       12,
			expectedallowedMaxForeignCountries: 8,
			expectedAllowedMaxHomeIPs:          8,
			expectedAllowedMaxHomeCountries:    8,
			expectedTrustedIPs:                 []string{},
			expectedTrustedCountries:           []string{},
			expectedHomeCountries:              &HomeCountries{},
		},
		{
			name:           "Set Trusted ForeignIPs and ForeignCountries",
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
			preDataallowedMaxForeignIPs:        8,
			preDataallowedMaxForeignCountries:  8,
			preDataAllowedMaxHomeIPs:           8,
			preDataAllowedMaxHomeCountries:     8,
			expectedallowedMaxForeignIPs:       10,
			expectedallowedMaxForeignCountries: 8,
			expectedAllowedMaxHomeIPs:          8,
			expectedAllowedMaxHomeCountries:    8,
			expectedTrustedIPs:                 []string{"192.168.1.1", "192.168.1.2"},
			expectedTrustedCountries:           []string{"DE", "US"},
			expectedHomeCountries:              &HomeCountries{},
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
			preDataallowedMaxForeignIPs:        15,
			preDataallowedMaxForeignCountries:  15,
			preDataAllowedMaxHomeIPs:           15,
			preDataAllowedMaxHomeCountries:     15,
			expectedallowedMaxForeignIPs:       15,
			expectedallowedMaxForeignCountries: 15,
			expectedAllowedMaxHomeIPs:          15,
			expectedAllowedMaxHomeCountries:    15,
			expectedTrustedIPs:                 []string{"172.16.0.1"},
			expectedTrustedCountries:           []string{"FR"},
			expectedHomeCountries:              &HomeCountries{Codes: []string{"US"}},
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
			preDataallowedMaxForeignIPs:        10,
			preDataallowedMaxForeignCountries:  10,
			preDataAllowedMaxHomeIPs:           10,
			preDataAllowedMaxHomeCountries:     10,
			expectedallowedMaxForeignIPs:       20,
			expectedallowedMaxForeignCountries: 10,
			expectedAllowedMaxHomeIPs:          10,
			expectedAllowedMaxHomeCountries:    10,
			expectedTrustedIPs:                 []string{"10.0.0.1", "10.0.0.2"},
			expectedTrustedCountries:           []string{"JP", "BR"},
			expectedHomeCountries:              &HomeCountries{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.customSettings != nil {
				tt.customSettings.Data = tt.dataCustomSettings
			}

			tt.allowedMaxForeignIPs = initializeIfNil(tt.allowedMaxForeignIPs, new(int)).(*int)
			tt.allowedMaxForeignCountries = initializeIfNil(tt.allowedMaxForeignCountries, new(int)).(*int)
			tt.allowedMaxHomeCountries = initializeIfNil(tt.allowedMaxHomeCountries, new(int)).(*int)
			tt.allowedMaxHomeIPs = initializeIfNil(tt.allowedMaxHomeIPs, new(int)).(*int)

			tt.trustedIPs = initializeIfNil(tt.trustedIPs, &[]string{}).(*[]string)
			tt.trustedCountries = initializeIfNil(tt.trustedCountries, &[]string{}).(*[]string)
			tt.homeCountries = initializeIfNil(tt.homeCountries, &HomeCountries{}).(*HomeCountries)

			*tt.allowedMaxForeignIPs = tt.preDataallowedMaxForeignIPs
			*tt.allowedMaxForeignCountries = tt.preDataallowedMaxForeignCountries
			*tt.allowedMaxHomeIPs = tt.preDataAllowedMaxHomeIPs
			*tt.allowedMaxHomeCountries = tt.preDataAllowedMaxHomeCountries

			applyCustomSettings(tt.customSettings, tt.sender, tt.allowedMaxForeignIPs, tt.allowedMaxForeignCountries, tt.trustedIPs, tt.trustedCountries, &tt.homeCountries.Codes, tt.allowedMaxHomeIPs, tt.allowedMaxHomeCountries)

			if *tt.allowedMaxForeignIPs != tt.expectedallowedMaxForeignIPs {
				t.Errorf("Expected Allowed Max ForeignIPs = %v, got = %v", tt.expectedallowedMaxForeignIPs, *tt.allowedMaxForeignIPs)
			}

			if *tt.allowedMaxForeignCountries != tt.expectedallowedMaxForeignCountries {
				t.Errorf("Expected Allowed Max ForeignCountries = %v, got = %v", tt.expectedallowedMaxForeignCountries, *tt.allowedMaxForeignCountries)
			}

			if *tt.allowedMaxHomeIPs != tt.expectedAllowedMaxHomeIPs {
				t.Errorf("Expected Allowed Max Home ForeignIPs = %v, got = %v", tt.expectedAllowedMaxHomeIPs, *tt.allowedMaxHomeIPs)
			}

			if *tt.allowedMaxHomeCountries != tt.expectedAllowedMaxHomeCountries {
				t.Errorf("Expected Allowed Max Home ForeignCountries = %v, got = %v", tt.expectedAllowedMaxHomeCountries, *tt.allowedMaxHomeCountries)
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
