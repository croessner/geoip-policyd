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

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
)

type LDAP struct {
	ServerURIs    []string
	BaseDN        string
	BindDN        string
	BindPWPATH    string
	Filter        string
	ResultAttr    []string
	StartTLS      bool
	TLSSkipVerify bool
	TLSCAFile     string
	TLSClientCert string
	TLSClientKey  string
	SASLExternal  bool
	Scope         int

	LDAPConn *ldap.Conn
	Mu       sync.Mutex
}

func (l *LDAP) String() string {
	var result string

	v := reflect.ValueOf(*l)
	typeOfc := v.Type()

	for i := 0; i < v.NumField(); i++ {
		switch typeOfc.Field(i).Name {
		case "LDAPConn", "Mu":
			continue
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfc.Field(i).Name, v.Field(i).Interface())
		}
	}

	return result[1:]
}

func (l *LDAP) Connect() {
	var (
		retryLimit   = 0
		ldapCounter  = 0
		err          error
		certificates []tls.Certificate
	)

	for {
		if retryLimit > maxRetries {
			log.Fatalln("Error: Could not connect to any LDAP servers")
		}

		if ldapCounter > len(l.ServerURIs)-1 {
			ldapCounter = 0
		}
		if cfg.Verbose == logLevelDebug {
			log.Printf("Debug: Trying %d/%d to connect to LDAP: %s\n",
				retryLimit+1, maxRetries+1, l.ServerURIs[ldapCounter])
		}
		l.LDAPConn, err = ldap.DialURL(l.ServerURIs[ldapCounter])
		if err != nil {
			ldapCounter += 1
			retryLimit += 1
			continue
		}

		if l.SASLExternal {
			// Certificates are not needed with ldapi//
			if l.TLSClientCert != "" && l.TLSClientKey != "" {
				cert, err := tls.LoadX509KeyPair(l.TLSClientCert, l.TLSClientKey)
				if err != nil {
					log.Fatal(err)
				}
				certificates = []tls.Certificate{cert}
			}
		}

		if l.StartTLS {
			// Load CA chain
			caCert, err := ioutil.ReadFile(l.TLSCAFile)
			if err != nil {
				log.Fatal("Error:", err)
				return
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			u, _ := url.Parse(l.ServerURIs[ldapCounter])
			host, _, _ := net.SplitHostPort(u.Host)

			tlsConfig := &tls.Config{
				Certificates:       certificates,
				RootCAs:            caCertPool,
				InsecureSkipVerify: l.TLSSkipVerify,
				ServerName:         host,
			}

			err = l.LDAPConn.StartTLS(tlsConfig)
			if err != nil {
				log.Println("Error:", err)
				//goland:noinspection GoUnreachableCode
				l.LDAPConn.Close()
				ldapCounter += 1
				retryLimit += 1
				continue
			}
		}
		break
	}

	if cfg.Verbose == logLevelDebug {
		log.Println("Debug: LDAP connection established")
	}
}

func (l *LDAP) Bind() {
	var (
		password []byte
		err      error
	)

	if l.SASLExternal {
		if cfg.Verbose == logLevelDebug {
			log.Println("Debug: LDAP: SASL/EXTERNAL")
		}
		err = l.LDAPConn.ExternalBind()
		if err != nil {
			log.Println("Error:", err)
		}
	} else {
		if cfg.Verbose == logLevelDebug {
			log.Println("Debug: LDAP: simple bind")
		}
		password, err = ioutil.ReadFile(l.BindPWPATH)
		if err != nil {
			log.Fatalln("Error:", err)
		}

		err = l.LDAPConn.Bind(l.BindDN, string(password))
		if err != nil {
			log.Println("Error:", err)
		}
	}
}

func (l *LDAP) Search(sender string) (string, error) {
	if strings.Contains(l.Filter, "%s") {
		filter := fmt.Sprintf(l.Filter, sender)
		if cfg.Verbose == logLevelDebug {
			log.Println("Debug: Using LDAP filter:", filter)
		}
		searchRequest := ldap.NewSearchRequest(
			l.BaseDN, l.Scope, ldap.NeverDerefAliases, 0, 0, false, filter, l.ResultAttr,
			nil,
		)

		searchResult, err := l.LDAPConn.Search(searchRequest)
		if err != nil {
			return "", err
		}

		for _, entry := range searchResult.Entries {
			result := entry.GetAttributeValue(l.ResultAttr[0])
			if cfg.Verbose == logLevelDebug {
				log.Printf("Debug: sender=%s; %s: %s=%v\n", sender, entry.DN, l.ResultAttr[0], result)
			}
			return result, nil
		}
	} else {
		log.Printf("Warning: LDAP filter does not contain '%%s' macro!\n")
	}

	return "", nil
}
