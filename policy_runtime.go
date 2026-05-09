package main

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/go-kit/log/level"
)

// NetworkMatcher stores parsed IP addresses and CIDR prefixes for repeated hot-path membership checks.
type NetworkMatcher struct {
	exact    map[netip.Addr]string
	prefixes []networkPrefix
}

// networkPrefix keeps a parsed prefix together with its original configuration value for logs.
type networkPrefix struct {
	prefix netip.Prefix
	raw    string
}

// NewNetworkMatcher parses configured IP and CIDR values once so requests do not repeat that work.
func NewNetworkMatcher(values []string) *NetworkMatcher {
	matcher := &NetworkMatcher{
		exact: make(map[netip.Addr]string),
	}

	for _, value := range values {
		if addr, err := netip.ParseAddr(value); err == nil {
			matcher.exact[addr] = value

			continue
		}

		if prefix, err := netip.ParsePrefix(value); err == nil {
			matcher.prefixes = append(matcher.prefixes, networkPrefix{prefix: prefix.Masked(), raw: value})
		}
	}

	return matcher
}

// ContainsString parses a request IP address and checks it against the compiled matcher.
func (m *NetworkMatcher) ContainsString(ip, guid string) bool {
	_, found := m.MatchString(ip, guid)

	return found
}

// MatchString parses a request IP address and returns the matched configured value when one exists.
func (m *NetworkMatcher) MatchString(ip, guid string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}

	return m.Match(addr, guid)
}

// Contains checks whether an already parsed request address is explicitly listed or inside a configured prefix.
func (m *NetworkMatcher) Contains(ip netip.Addr, guid string) bool {
	_, found := m.Match(ip, guid)

	return found
}

// Match checks an already parsed request address and returns the matched configured value when one exists.
func (m *NetworkMatcher) Match(ip netip.Addr, guid string) (string, bool) {
	if m == nil {
		return "", false
	}

	if raw, found := m.exact[ip]; found {
		if isDebugLoggingEnabled() {
			_ = level.Debug(logger).Log("guid", guid, "msg", "IP matched", "ip_address", ip.String())
		}

		return raw, true
	}

	for _, network := range m.prefixes {
		if isDebugLoggingEnabled() {
			_ = level.Debug(logger).Log("guid", guid, "msg", "Checking", "ip_address", ip.String(), "trusted_network", network.prefix.String())
		}

		if network.prefix.Contains(ip) {
			if isDebugLoggingEnabled() {
				_ = level.Debug(logger).Log("guid", guid, "msg", "IP matched", "ip_address", ip.String())
			}

			return network.raw, true
		}
	}

	return "", false
}

// CountrySet stores normalized country codes for repeated case-insensitive checks.
type CountrySet struct {
	codes map[string]struct{}
}

// NewCountrySet normalizes configured country codes into a lookup set.
func NewCountrySet(countries []string) *CountrySet {
	set := &CountrySet{
		codes: make(map[string]struct{}, len(countries)),
	}

	for _, country := range countries {
		set.codes[strings.ToUpper(country)] = struct{}{}
	}

	return set
}

// Contains reports whether the supplied country code is present in the set.
func (s *CountrySet) Contains(countryCode string) bool {
	if s == nil {
		return false
	}

	_, found := s.codes[strings.ToUpper(countryCode)]

	return found
}

// PolicySettings owns the effective limits and compiled trust/home matchers for one policy evaluation.
type PolicySettings struct {
	TrustedIPs                 []string
	TrustedCountries           []string
	HomeCountries              []string
	AllowedMaxForeignIPs       int
	AllowedMaxHomeIPs          int
	AllowedMaxForeignCountries int
	AllowedMaxHomeCountries    int

	trustedIPMatcher  *NetworkMatcher
	trustedCountrySet *CountrySet
	homeCountrySet    *CountrySet
}

// NewPolicySettingsFromConfig builds the default policy settings from the command-line configuration.
func NewPolicySettingsFromConfig(config *CmdLineConfig) *PolicySettings {
	if config == nil {
		return &PolicySettings{}
	}

	settings := &PolicySettings{
		TrustedIPs:                 []string{},
		TrustedCountries:           []string{},
		HomeCountries:              config.HomeCountries,
		AllowedMaxForeignIPs:       config.MaxIPs,
		AllowedMaxHomeIPs:          config.MaxHomeIPs,
		AllowedMaxForeignCountries: config.MaxCountries,
		AllowedMaxHomeCountries:    config.MaxHomeCountries,
	}

	settings.compileMatchers()

	return settings
}

// NewPolicySettings constructs a complete policy settings object for tests and compatibility wrappers.
func NewPolicySettings(trustedIPs, trustedCountries, homeCountries []string, allowedMaxForeignIPs, allowedMaxHomeIPs, allowedMaxForeignCountries, allowedMaxHomeCountries int) *PolicySettings {
	settings := &PolicySettings{
		TrustedIPs:                 trustedIPs,
		TrustedCountries:           trustedCountries,
		HomeCountries:              homeCountries,
		AllowedMaxForeignIPs:       allowedMaxForeignIPs,
		AllowedMaxHomeIPs:          allowedMaxHomeIPs,
		AllowedMaxForeignCountries: allowedMaxForeignCountries,
		AllowedMaxHomeCountries:    allowedMaxHomeCountries,
	}

	settings.compileMatchers()

	return settings
}

// Clone returns a request-local settings copy that custom settings can change without mutating defaults.
func (s *PolicySettings) Clone() *PolicySettings {
	if s == nil {
		return &PolicySettings{}
	}

	return &PolicySettings{
		TrustedIPs:                 s.TrustedIPs,
		TrustedCountries:           s.TrustedCountries,
		HomeCountries:              s.HomeCountries,
		AllowedMaxForeignIPs:       s.AllowedMaxForeignIPs,
		AllowedMaxHomeIPs:          s.AllowedMaxHomeIPs,
		AllowedMaxForeignCountries: s.AllowedMaxForeignCountries,
		AllowedMaxHomeCountries:    s.AllowedMaxHomeCountries,
		trustedIPMatcher:           s.trustedIPMatcher,
		trustedCountrySet:          s.trustedCountrySet,
		homeCountrySet:             s.homeCountrySet,
	}
}

// compileMatchers refreshes derived matchers after the plain settings values are changed together.
func (s *PolicySettings) compileMatchers() {
	s.trustedIPMatcher = NewNetworkMatcher(s.TrustedIPs)
	s.trustedCountrySet = NewCountrySet(s.TrustedCountries)
	s.homeCountrySet = NewCountrySet(s.HomeCountries)
}

// CheckHomeCountry records the current IP and country as home data when the country matches the effective home set.
func (s *PolicySettings) CheckHomeCountry(remoteClient *RemoteClient, countryCode, clientIP, guid string) bool {
	if s == nil || countryCode == "" || !s.homeCountrySet.Contains(countryCode) {
		return false
	}

	if isDebugLoggingEnabled() {
		_ = level.Debug(logger).Log("guid", guid, "msg", "Country matched", "home_country", countryCode)
	}

	remoteClient.AddHomeIPAddress(clientIP)
	remoteClient.AddHomeCountryCode(countryCode)

	return true
}

// CheckCountryPolicy applies country trust and count limits to the remote client state.
func (s *PolicySettings) CheckCountryPolicy(remoteClient *RemoteClient, countryCode string, policyResponse *PolicyResponse, _ string, isHome bool) bool {
	if countryCode == "" {
		return false
	}

	if len(s.TrustedCountries) > 0 {
		if s.trustedCountrySet.Contains(countryCode) {
			return false
		}

		policyResponse.fired = true

		if config.BlockPermanent {
			remoteClient.Locked = true
		}

		return true
	}

	if !isHome {
		remoteClient.AddForeignCountryCode(countryCode)
	}

	if len(remoteClient.ForeignCountries) > s.AllowedMaxForeignCountries ||
		(remoteClient.haveHomeCountries() && len(remoteClient.HomeCountries.Countries) > s.AllowedMaxHomeCountries) {
		policyResponse.fired = true

		if config.BlockPermanent {
			remoteClient.Locked = true
		}

		return true
	}

	return false
}

// CheckIPPolicy applies IP trust and count limits to the remote client state.
func (s *PolicySettings) CheckIPPolicy(remoteClient *RemoteClient, clientIP string, policyResponse *PolicyResponse, guid string, isHome bool) bool {
	if clientIP == "" {
		return false
	}

	if len(s.TrustedIPs) > 0 {
		if s.trustedIPMatcher.ContainsString(clientIP, guid) {
			return false
		}

		policyResponse.fired = true

		if config.BlockPermanent {
			remoteClient.Locked = true
		}

		return true
	}

	if !isHome {
		remoteClient.AddForeignIPAddress(clientIP)
	}

	if len(remoteClient.ForeignIPs) > s.AllowedMaxForeignIPs ||
		(remoteClient.haveHomeIPs() && len(remoteClient.HomeCountries.IPs) > s.AllowedMaxHomeIPs) {
		policyResponse.fired = true

		if config.BlockPermanent {
			remoteClient.Locked = true
		}

		return true
	}

	return false
}

// Evaluate applies home detection, country policy, and IP policy in the same order as the legacy hotpath.
func (s *PolicySettings) Evaluate(remoteClient *RemoteClient, countryCode string, policyResponse *PolicyResponse, clientIP, guid string) bool {
	isHome := s.CheckHomeCountry(remoteClient, countryCode, clientIP, guid)

	return s.CheckCountryPolicy(remoteClient, countryCode, policyResponse, guid, isHome) ||
		s.CheckIPPolicy(remoteClient, clientIP, policyResponse, guid, isHome)
}

// CompilePolicyRuntime precomputes matchers that are derived from static command-line configuration.
func (c *CmdLineConfig) CompilePolicyRuntime() {
	if c == nil {
		return
	}

	c.policySettings = NewPolicySettingsFromConfig(c)
	c.ignoreNetworkMatcher = NewNetworkMatcher(c.IgnoreNets)
}

// PolicySettings returns a request-local copy of the compiled default policy settings.
func (c *CmdLineConfig) PolicySettings() *PolicySettings {
	if c == nil {
		return &PolicySettings{}
	}

	if c.policySettings == nil {
		return NewPolicySettingsFromConfig(c)
	}

	return c.policySettings.Clone()
}

// IgnoreNetworkMatcher returns the compiled ignore-network matcher, building a temporary matcher for test-only configs.
func (c *CmdLineConfig) IgnoreNetworkMatcher() *NetworkMatcher {
	if c == nil {
		return NewNetworkMatcher(nil)
	}

	if c.ignoreNetworkMatcher == nil {
		return NewNetworkMatcher(c.IgnoreNets)
	}

	return c.ignoreNetworkMatcher
}

// CompiledAccountSettings stores derived matchers for one custom settings account entry.
type CompiledAccountSettings struct {
	account Account

	trustedIPMatcher  *NetworkMatcher
	trustedCountrySet *CountrySet
	homeCountrySet    *CountrySet
}

// NewCompiledAccountSettings compiles a custom account entry into reusable matchers.
func NewCompiledAccountSettings(account Account) *CompiledAccountSettings {
	return &CompiledAccountSettings{
		account:           account,
		trustedIPMatcher:  NewNetworkMatcher(account.TrustedIPs),
		trustedCountrySet: NewCountrySet(account.TrustedCountries),
		homeCountrySet:    NewCountrySet(accountHomeCountries(account)),
	}
}

// ApplyTo overlays the compiled custom account values onto request-local policy settings.
func (s *CompiledAccountSettings) ApplyTo(policySettings *PolicySettings) {
	if s == nil || policySettings == nil {
		return
	}

	if s.account.IPs > 0 {
		policySettings.AllowedMaxForeignIPs = s.account.IPs
	}

	if s.account.Countries > 0 {
		policySettings.AllowedMaxForeignCountries = s.account.Countries
	}

	if len(s.account.TrustedIPs) > 0 {
		policySettings.TrustedIPs = s.account.TrustedIPs
		policySettings.trustedIPMatcher = s.trustedIPMatcher
	}

	if len(s.account.TrustedCountries) > 0 {
		policySettings.TrustedCountries = s.account.TrustedCountries
		policySettings.trustedCountrySet = s.trustedCountrySet
	}

	homeCountries := s.account.HomeCountries
	if homeCountries != nil && len(homeCountries.Codes) > 0 {
		policySettings.HomeCountries = homeCountries.Codes
		policySettings.homeCountrySet = s.homeCountrySet

		if homeCountries.IPs > 0 {
			policySettings.AllowedMaxHomeIPs = homeCountries.IPs
		}

		if homeCountries.Countries > 0 {
			policySettings.AllowedMaxHomeCountries = homeCountries.Countries
		}
	}
}

// accountHomeCountries extracts the optional home-country code list from a custom account entry.
func accountHomeCountries(account Account) []string {
	if account.HomeCountries == nil {
		return nil
	}

	homeCountries := account.HomeCountries

	return homeCountries.Codes
}

// Clone returns an unpublished copy of custom settings so HTTP mutations do not race with active readers.
func (s *CustomSettings) Clone() *CustomSettings {
	if s == nil {
		return nil
	}

	clone := &CustomSettings{Data: make([]Account, 0, len(s.Data))}
	for _, account := range s.Data {
		clone.Data = append(clone.Data, cloneAccount(account))
	}

	return clone
}

// cloneAccount deep-copies nested slices and optional home settings for one custom account entry.
func cloneAccount(account Account) Account {
	account.TrustedCountries = slices.Clone(account.TrustedCountries)
	account.TrustedIPs = slices.Clone(account.TrustedIPs)

	if account.HomeCountries != nil {
		homeCountries := *account.HomeCountries
		homeCountries.Codes = slices.Clone(homeCountries.Codes)
		account.HomeCountries = &homeCountries
	}

	return account
}

// Compile builds the sender lookup index and per-account matchers for custom settings.
func (s *CustomSettings) Compile() {
	if s == nil {
		return
	}

	compiled := make(map[string]*CompiledAccountSettings, len(s.Data))
	for _, account := range s.Data {
		if account.Sender == "" {
			continue
		}

		compiled[account.Sender] = NewCompiledAccountSettings(account)
	}

	s.compiled = compiled
}

// ApplyTo overlays sender-specific custom settings onto the supplied request-local policy settings.
func (s *CustomSettings) ApplyTo(sender string, policySettings *PolicySettings) {
	if s == nil {
		return
	}

	if s.compiled != nil {
		if account, found := s.compiled[sender]; found {
			account.ApplyTo(policySettings)
		}

		return
	}

	for _, account := range s.Data {
		if account.Sender != sender {
			continue
		}

		NewCompiledAccountSettings(account).ApplyTo(policySettings)

		return
	}
}

// storeCustomSettings compiles custom settings before publishing them through the shared atomic store.
func storeCustomSettings(settings *CustomSettings) {
	if settings != nil {
		settings.Compile()
	}

	customSettingsStore.Store(settings)
}

// loadCustomSettings returns the current custom settings pointer from the atomic store when initialized.
func loadCustomSettings() *CustomSettings {
	value := customSettingsStore.Load()
	if value == nil {
		return nil
	}

	settings, _ := value.(*CustomSettings)

	return settings
}
