/*
geoip-policyd
Copyright (C) 2021  Rößner-Network-Solutions

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import "errors"

// action.
var (
	errOperatorFromEmpty = errors.New("operator 'from' must not be empty")
	errOperatorToEmpty   = errors.New("operator 'to' must not be empty")
	errMacroPercentS     = errors.New("email message file must contain a macro '%%s' for the sender")
	errMacroPercentSOnce = errors.New("email message file must contain exactly one '%%s' macro for the sender")
)

// config.
var (
	errNotIPOrHostname    = errors.New("argument is not a valid IP address or hostname")
	errNotInteger         = errors.New("argument is not an integer")
	errNotValidPortNumber = errors.New("argument is not a valid port number")
	errFileNotFound       = errors.New("file not found")
	errMaxCountries       = errors.New("argument must be an unsigned integer and greater or equal than 0")
	errMaxIPs             = errors.New("argument must be an unsigned integer")
	errPoolSize           = errors.New("argument must be an unsigned integer and not 0")
	errIdlePoolSize       = errors.New("argument must be an unsigned integer")
	errLDAPScope          = errors.New("argument must be one of: 'one', 'base' or 'sub'")
)

// ldap.
var errLDAPConnect = errors.New("could not connect to any LDAP servers")

// httpapp.
var (
	errWrongCT                 = errors.New("wrong Content-Type header")
	errValueMustBeString       = errors.New("value must be string")
	errValueMustNotBeEmpty     = errors.New("value must not be empty")
	errUnknownKey              = errors.New("unknown key")
	errValueFormat             = errors.New("wrong value format")
	errNoAddressNORSender      = errors.New("value does not contain 'address' and 'sender' fields")
	errCommentNotString        = errors.New("'comment' is not a string")
	errCountriesNotFloat64     = errors.New("'countries' is not a float64")
	errIPsNotFloat64           = errors.New("'ips' is not a float64")
	errSenderNotString         = errors.New("'sender' is not a string")
	errCountriesLowerThantZero = errors.New("'countries' lower than zero")
	errIPsLowerThanZero        = errors.New("'ips' lower than zero")
	errSenderEmpty             = errors.New("'sender' is empty")
	errValueNotString          = errors.New("value must be string")
	errValueEmpty              = errors.New("value must not be empty")
	errSenderNotFound          = errors.New("'sender' not found")
	errOnlyAllow               = errors.New("only command=allow supported")
)

// policy.
var (
	errPolicyProtocol = errors.New("protocol error")
)
