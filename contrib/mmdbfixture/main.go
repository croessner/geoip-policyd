// Copyright (C) 2026 Christian Rößner
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

// Command mmdbfixture generates the small synthetic MMDB fixtures used by the
// geoip-policyd unit tests. It lives in its own Go module so the writer
// dependency never enters the vendored runtime module.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// fixtureBuildEpoch pins the metadata build time so regenerated fixtures are byte-for-byte reproducible.
// The value is 2026-09-24T00:00:00Z; the fixtures are intentionally allowed to become "stale" in tests.
const fixtureBuildEpoch = 1790208000

// fixtureNetwork binds one CIDR to the record stored for it.
type fixtureNetwork struct {
	cidr   string
	record mmdbtype.Map
}

// fixture describes one MMDB file: its metadata type and its networks.
type fixture struct {
	fileName     string
	databaseType string
	description  string
	networks     []fixtureNetwork
}

// fixtureWriter renders fixtures into a target directory.
type fixtureWriter struct {
	outputDir string
}

// newFixtureWriter creates a writer that stores fixtures below outputDir.
func newFixtureWriter(outputDir string) *fixtureWriter {
	return &fixtureWriter{outputDir: outputDir}
}

// Write builds the MMDB tree for f and writes it atomically to the output directory.
func (w *fixtureWriter) Write(f fixture) error {
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		BuildEpoch:              fixtureBuildEpoch,
		DatabaseType:            f.databaseType,
		Description:             map[string]string{"en": f.description},
		IncludeReservedNetworks: true,
		IPVersion:               6,
		RecordSize:              24,
	})
	if err != nil {
		return fmt.Errorf("create tree for %s: %w", f.fileName, err)
	}

	for _, network := range f.networks {
		_, ipNet, parseErr := net.ParseCIDR(network.cidr)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", network.cidr, parseErr)
		}

		if insertErr := tree.Insert(ipNet, network.record); insertErr != nil {
			return fmt.Errorf("insert %s: %w", network.cidr, insertErr)
		}
	}

	target := filepath.Join(w.outputDir, f.fileName)
	tmp := target + ".tmp"

	file, err := os.Create(tmp)
	if err != nil {
		return err
	}

	if _, err = tree.WriteTo(file); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)

		return fmt.Errorf("write %s: %w", f.fileName, err)
	}

	if err = file.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, target)
}

// ipInfoLiteRecord returns a flat IPinfo Lite record; asn fields are optional like in the real data.
func ipInfoLiteRecord(countryCode, country, continentCode, continent, asn, asName, asDomain string) mmdbtype.Map {
	record := mmdbtype.Map{
		"country":        mmdbtype.String(country),
		"country_code":   mmdbtype.String(countryCode),
		"continent":      mmdbtype.String(continent),
		"continent_code": mmdbtype.String(continentCode),
	}

	if asn != "" {
		record["asn"] = mmdbtype.String(asn)
		record["as_name"] = mmdbtype.String(asName)
		record["as_domain"] = mmdbtype.String(asDomain)
	}

	return record
}

// fixtures lists every generated test database.
func fixtures() []fixture {
	return []fixture{
		{
			fileName:     "IPinfo-Lite-Test.mmdb",
			databaseType: "ipinfo bundle_location_lite.mmdb",
			description:  "Synthetic IPinfo Lite test database for geoip-policyd",
			networks: []fixtureNetwork{
				{"81.2.69.0/24", ipInfoLiteRecord("GB", "United Kingdom", "EU", "Europe", "AS20712", "Andrews & Arnold Ltd", "aa.net.uk")},
				{"89.160.20.0/24", ipInfoLiteRecord("SE", "Sweden", "EU", "Europe", "", "", "")},
				{"2001:db8:1::/48", ipInfoLiteRecord("DE", "Germany", "EU", "Europe", "AS64496", "Example Networks", "example.net")},
			},
		},
		{
			fileName:     "IPinfo-Legacy-Test.mmdb",
			databaseType: "ipinfo country_asn.mmdb",
			description:  "Synthetic legacy IPinfo country_asn test database for geoip-policyd",
			networks: []fixtureNetwork{
				{"81.2.69.0/24", mmdbtype.Map{
					"country":      mmdbtype.String("GB"),
					"country_name": mmdbtype.String("United Kingdom"),
					"asn":          mmdbtype.String("AS20712"),
				}},
			},
		},
		{
			fileName:     "GeoLite2-ASN-Test.mmdb",
			databaseType: "GeoLite2-ASN",
			description:  "Synthetic ASN-only test database for geoip-policyd",
			networks: []fixtureNetwork{
				{"81.2.69.0/24", mmdbtype.Map{
					"autonomous_system_number":       mmdbtype.Uint32(20712),
					"autonomous_system_organization": mmdbtype.String("Andrews & Arnold Ltd"),
				}},
			},
		},
	}
}

// main generates all fixtures into the directory given by -out.
func main() {
	outputDir := flag.String("out", "../../testdata", "directory that receives the generated MMDB fixtures")
	flag.Parse()

	writer := newFixtureWriter(*outputDir)

	for _, f := range fixtures() {
		if err := writer.Write(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		fmt.Println("wrote", filepath.Join(*outputDir, f.fileName))
	}
}
