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
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
)

// validationMessageFormatter turns a validator field error into a stable diagnostic.
type validationMessageFormatter func(validator.FieldError) string

var validationMessageFormatters = map[string]validationMessageFormatter{
	"required": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' is required but missing or empty", e.Field())
	},
	"required_if": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' is required when %s", e.Field(), e.Param())
	},
	"min": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must be at least %s (got %v)", e.Field(), e.Param(), e.Value())
	},
	"max": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must be at most %s (got %v)", e.Field(), e.Param(), e.Value())
	},
	"ip": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must be a valid IP address (got '%v')", e.Field(), e.Value())
	},
	"hostname_rfc1123": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must be a valid IP address or hostname (got '%v')", e.Field(), e.Value())
	},
	"email": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must be a valid e-mail address (got '%v')", e.Field(), e.Value())
	},
	"file": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must be a path to an existing file (got '%v')", e.Field(), e.Value())
	},
	"iso3166_1_alpha2": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' contains an invalid ISO 3166-1 alpha-2 country code (got '%v')", e.Field(), e.Value())
	},
	"ldap_uri": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must be a valid LDAP URI (ldap://, ldaps://, or ldapi://) (got '%v')", e.Field(), e.Value())
	},
	"cidr_or_ip": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must be a valid IP address or CIDR notation (got '%v')", e.Field(), e.Value())
	},
	"contains": func(e validator.FieldError) string {
		return fmt.Sprintf("'%s' must contain the substring '%s' (got '%v')", e.Field(), e.Param(), e.Value())
	},
}

// validateLDAPURI validates that a string is a valid LDAP URI.
// Accepted schemes: ldap://, ldaps://, ldapi://
func validateLDAPURI(fl validator.FieldLevel) bool {
	uri := fl.Field().String()

	return strings.HasPrefix(uri, "ldap://") ||
		strings.HasPrefix(uri, "ldaps://") ||
		strings.HasPrefix(uri, "ldapi://")
}

// validateCIDROrIP validates that a string is a valid IP address or CIDR network notation.
func validateCIDROrIP(fl validator.FieldLevel) bool {
	value := fl.Field().String()

	if net.ParseIP(value) != nil {
		return true
	}

	_, _, err := net.ParseCIDR(value)

	return err == nil
}

// newValidator creates a validator instance with all custom validators registered.
func newValidator() (*validator.Validate, error) {
	v := validator.New()

	if err := v.RegisterValidation("ldap_uri", validateLDAPURI); err != nil {
		return nil, fmt.Errorf("registering ldap_uri validator: %w", err)
	}

	if err := v.RegisterValidation("cidr_or_ip", validateCIDROrIP); err != nil {
		return nil, fmt.Errorf("registering cidr_or_ip validator: %w", err)
	}

	return v, nil
}

// formatValidationErrors formats validator.ValidationErrors into a human-readable error message.
func formatValidationErrors(err error) error {
	var validationErrors validator.ValidationErrors
	if !errors.As(err, &validationErrors) {
		return err
	}

	msgs := make([]string, 0, len(validationErrors))

	for _, e := range validationErrors {
		msgs = append(msgs, formatValidationError(e))
	}

	return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(msgs, "\n  - "))
}

// formatValidationError formats one validator field error for an operator.
func formatValidationError(e validator.FieldError) string {
	if formatter, ok := validationMessageFormatters[e.Tag()]; ok {
		return formatter(e)
	}

	return fmt.Sprintf("'%s' failed validation '%s' (got '%v')", e.Field(), e.Tag(), e.Value())
}

// Validate validates the server configuration after Init() has been called.
// It must only be called when CommandServer is true.
// Returns a combined error describing all validation failures, or nil if valid.
func (c *CmdLineConfig) Validate() error {
	v, err := newValidator()
	if err != nil {
		return err
	}

	if err := c.validateServiceSelection(); err != nil {
		return err
	}

	if err := c.validateListenerSettings(v); err != nil {
		return err
	}

	if err := c.validateStructs(v); err != nil {
		return err
	}

	if err := c.validateHTTPSettings(); err != nil {
		return err
	}

	return c.validateObservabilitySettings()
}

// validateServiceSelection ensures the process exposes at least one listener.
func (c *CmdLineConfig) validateServiceSelection() error {
	if !c.PolicyServiceEnabled() && !c.HTTPServiceEnabled() {
		return errors.New("at least one listener must remain enabled; remove either 'disable-policy-service' or 'disable-http-service'")
	}

	return nil
}

// validateListenerSettings validates bind address and port fields for enabled listeners only.
func (c *CmdLineConfig) validateListenerSettings(v *validator.Validate) error {
	if c.PolicyServiceEnabled() {
		if err := validateListenerAddress(v, "server-address", c.ServerAddress); err != nil {
			return err
		}

		if err := validateListenerPort("server-port", c.ServerPort); err != nil {
			return err
		}
	}

	if c.HTTPServiceEnabled() {
		if err := validateListenerAddress(v, "http-address", c.HTTPAddress); err != nil {
			return err
		}

		if err := validateListenerPort("http-port", c.HTTPPort); err != nil {
			return err
		}
	}

	return nil
}

// validateListenerAddress checks that a listener address is an IP address or RFC 1123 hostname.
func validateListenerAddress(v *validator.Validate, name string, value string) error {
	if err := v.Var(value, "ip|hostname_rfc1123"); err != nil {
		return fmt.Errorf("'%s' must be a valid IP address or hostname (got '%s')", name, value)
	}

	return nil
}

// validateListenerPort checks the TCP port range accepted by net.Listen.
func validateListenerPort(name string, value int) error {
	if value < 1 || value > 65535 {
		return fmt.Errorf("'%s' must be between 1 and 65535 (got %d)", name, value)
	}

	return nil
}

// validateStructs validates exported configuration fields and optional nested LDAP fields.
func (c *CmdLineConfig) validateStructs(v *validator.Validate) error {
	if err := v.Struct(c); err != nil {
		return formatValidationErrors(err)
	}

	// The embedded *LdapConf pointer is not traversed automatically by the validator when
	// it is nil, so we validate it separately when LDAP is enabled.
	if c.UseLDAP && c.LdapConf != nil {
		if err := v.Struct(c.LdapConf); err != nil {
			return formatValidationErrors(err)
		}
	}

	return nil
}

// validateHTTPSettings validates unexported HTTPApp fields that struct tags cannot see.
func (c *CmdLineConfig) validateHTTPSettings() error {
	if !c.HTTPServiceEnabled() {
		return nil
	}

	// HTTPApp contains only unexported fields which are invisible to the struct validator.
	// Validate them programmatically.
	if c.useBasicAuth {
		if c.auth.username == "" {
			return errors.New("'http-basic-auth-username' is required when http-use-basic-auth is enabled")
		}

		if c.auth.password == "" {
			return errors.New("'http-basic-auth-password' is required when http-use-basic-auth is enabled")
		}
	}

	if c.useSSL {
		if _, err := os.Stat(c.x509.cert); err != nil {
			return fmt.Errorf("'http-tls-cert': file '%s' does not exist or is not accessible", c.x509.cert)
		}

		if _, err := os.Stat(c.x509.key); err != nil {
			return fmt.Errorf("'http-tls-key': file '%s' does not exist or is not accessible", c.x509.key)
		}
	}

	return nil
}

// validateObservabilitySettings validates metrics and tracing cross-field constraints.
func (c *CmdLineConfig) validateObservabilitySettings() error {
	if c.Observability.PrometheusEnabled {
		if !c.HTTPServiceEnabled() {
			return errors.New("'disable-http-service' cannot be used when prometheus is enabled")
		}

		if c.Observability.PrometheusPath == "" || !strings.HasPrefix(c.Observability.PrometheusPath, "/") {
			return errors.New("'prometheus-path' must start with '/' when prometheus is enabled")
		}

		if c.Observability.PrometheusPath == "/" {
			return errors.New("'prometheus-path' must not be '/'")
		}
	}

	if c.Observability.OTelSampleRatio < 0 || c.Observability.OTelSampleRatio > 1 {
		return errors.New("'otel-sample-ratio' must be between 0.0 and 1.0")
	}

	if c.Observability.OTelEnabled {
		if !c.Observability.OTelTracesEnabled && !c.Observability.OTelMetricsEnabled {
			return errors.New("at least one of 'otel-traces-enabled' or 'otel-metrics-enabled' must be enabled when otel is enabled")
		}

		if c.Observability.OTLPEndpoint == "" {
			return errors.New("'otel-exporter-otlp-endpoint' is required when otel is enabled")
		}
	}

	return nil
}
