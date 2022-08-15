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
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
)

type LDAP struct {
	StartTLS      bool
	TLSSkipVerify bool
	SASLExternal  bool

	PoolSize int
	Scope    int

	BaseDN        string
	BindDN        string
	BindPW        string
	Filter        string
	TLSCAFile     string
	TLSClientCert string
	TLSClientKey  string

	ServerURIs []string
	ResultAttr []string

	Mu   *sync.Mutex
	Conn *ldap.Conn
}

type LdapRequest struct {
	username   string
	filter     string
	guid       string
	attributes []string
	replyChan  chan LdapReply
}

type LdapReply struct {
	dn     string
	result map[string][]string
	err    error
}

func (l *LDAP) String() string {
	var result string

	value := reflect.ValueOf(*l)
	typeOfValue := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfValue.Field(index).Name {
		case "Mu", "Conn":
			continue
		case "BindPW":
			result += fmt.Sprintf(" %s='<hidden>'", typeOfValue.Field(index).Name)
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
		}
	}

	return result[1:]
}

func (l *LDAP) isClosing() bool {
	return l.Conn.IsClosing()
}

func (l *LDAP) connect(guid string) error {
	l.Mu.Lock()
	defer l.Mu.Unlock()

	var (
		retryLimit   = 0
		ldapCounter  = 0
		err          error
		certificates []tls.Certificate
	)

	for {
		if retryLimit > ldapMaxRetries {
			return errLDAPConnect
		}

		if ldapCounter > len(l.ServerURIs)-1 {
			ldapCounter = 0
		}

		level.Debug(logger).Log(
			"guid", guid,
			"ldap_uri", l.ServerURIs[ldapCounter],
			"current_attempt", retryLimit+1,
			"max_attempt", ldapMaxRetries+1,
		)

		l.Conn, err = ldap.DialURL(l.ServerURIs[ldapCounter])
		if err != nil {
			ldapCounter++
			retryLimit++

			continue
		}

		if l.SASLExternal {
			// Certificates are not needed with ldapi//
			if l.TLSClientCert != "" && l.TLSClientKey != "" {
				cert, err := tls.LoadX509KeyPair(l.TLSClientCert, l.TLSClientKey)
				if err != nil {
					return err
				}

				certificates = []tls.Certificate{cert}
			}
		}

		if l.StartTLS {
			// Load CA chain
			caCert, err := os.ReadFile(l.TLSCAFile)
			if err != nil {
				return err
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			u, _ := url.Parse(l.ServerURIs[ldapCounter])

			host, _, err := net.SplitHostPort(u.Host)
			if err != nil {
				return err
			}

			tlsConfig := &tls.Config{
				Certificates:       certificates,
				RootCAs:            caCertPool,
				InsecureSkipVerify: l.TLSSkipVerify, //nolint:gosec // Support self-signed certificates
				ServerName:         host,
			}

			err = l.Conn.StartTLS(tlsConfig)
			if err != nil {
				return err
			}

			level.Debug(logger).Log("guid", guid, "msg", "STARTTLS")
		}

		break
	}

	level.Debug(logger).Log("guid", guid, "msg", "Connection established")

	return nil
}

func (l *LDAP) bind(guid string) error {
	l.Mu.Lock()
	defer l.Mu.Unlock()

	var err error

	if l.SASLExternal {
		level.Debug(logger).Log("guid", guid, "msg", "SASL/EXTERNAL")

		err = l.Conn.ExternalBind()
		if err != nil {
			return err
		}
	} else {
		level.Debug(logger).Log("guid", guid, "msg", "simple bind")
		level.Debug(logger).Log("guid", guid, "bind_dn", l.BindDN)

		_, err = l.Conn.SimpleBind(&ldap.SimpleBindRequest{
			Username: l.BindDN,
			Password: l.BindPW,
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func (l *LDAP) unbind() error {
	l.Mu.Lock()
	defer l.Mu.Unlock()

	if err := l.Conn.Unbind(); err != nil {
		return err
	}

	return nil
}

//nolint:nonamedreturns // Making use of the names
func (l *LDAP) search(guid, lookupValue, filter string, attributes []string) (
	dn string, result map[string][]string, err error,
) {
	l.Mu.Lock()
	defer l.Mu.Unlock()

	if strings.Contains(filter, "%s") {
		filter = strings.ReplaceAll(filter, "%s", lookupValue)
	}

	re := regexp.MustCompile(`\s`)
	filter = re.ReplaceAllString(filter, "")

	level.Debug(logger).Log("guid", guid, "filter", filter)

	searchRequest := ldap.NewSearchRequest(
		l.BaseDN, l.Scope, ldap.NeverDerefAliases, 0, 0, false, filter, attributes,
		nil,
	)

	searchResult, err := l.Conn.Search(searchRequest)
	if err != nil {
		return "", nil, err
	}

	result = make(map[string][]string)

	for _, entry := range searchResult.Entries {
		for _, attrName := range attributes {
			values := entry.GetAttributeValues(attrName)

			if len(result[attrName]) > 0 {
				result[attrName] = append(result[attrName], values...)
			} else {
				result[attrName] = values
			}
		}

		// Note: Only the first DN is currently stored!
		if dn == "" {
			dn = entry.DN
		}
	}

	return dn, result, nil
}

//nolint:gocognit // Ignore
func ldapWorker() {
	var (
		err  error
		args LdapRequest
	)

	ldapInstance := make([]LDAP, config.LDAP.PoolSize)
	ldapAliveEnd := make(chan bool)

	for instance := 0; instance < config.LDAP.PoolSize; instance++ {
		ldapInstance[instance].ServerURIs = config.LDAP.ServerURIs
		ldapInstance[instance].BaseDN = config.LDAP.BaseDN
		ldapInstance[instance].BindDN = config.LDAP.BindDN
		ldapInstance[instance].BindPW = config.LDAP.BindPW
		ldapInstance[instance].StartTLS = config.LDAP.StartTLS
		ldapInstance[instance].TLSSkipVerify = config.LDAP.TLSSkipVerify
		ldapInstance[instance].TLSCAFile = config.LDAP.TLSCAFile
		ldapInstance[instance].TLSClientCert = config.LDAP.TLSClientCert
		ldapInstance[instance].TLSClientKey = config.LDAP.TLSClientKey
		ldapInstance[instance].SASLExternal = config.LDAP.SASLExternal
		ldapInstance[instance].Scope = config.LDAP.Scope
		ldapInstance[instance].Mu = &sync.Mutex{}

		level.Debug(logger).Log("instance", instance+1, "ldap", ldapInstance[instance].String())

		err = ldapInstance[instance].connect(fmt.Sprintf("main-%d", instance))
		if err != nil {
			level.Error(logger).Log("instance", instance+1, "error", err.Error())
		} else {
			err = ldapInstance[instance].bind(fmt.Sprintf("main-%d", instance))
			if err != nil {
				level.Error(logger).Log("instance", instance+1, "error", err.Error())
			}
		}

		go func(index int) {
			searchRequest := ldap.NewSearchRequest(
				//nolint:gomnd // These values are fine
				"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=*)", []string{"1.1"},
				nil,
			)

			//nolint:gomnd // Time factor
			ticker := time.NewTicker(30 * time.Second)

			for {
				select {
				case <-ticker.C:
					level.Debug(logger).Log(
						"instance", index+1, "msg", fmt.Sprintf("Keep alive check for connection #%d", index+1),
					)

					if !(ldapInstance[index].Conn == nil || ldapInstance[index].Conn.IsClosing()) {
						_, err := ldapInstance[index].Conn.Search(searchRequest)
						if err != nil {
							level.Warn(logger).Log("instance", index+1, "warn", err.Error())

							ldapInstance[index].Mu.Lock()
							ldapInstance[index].Conn = nil
							ldapInstance[index].Mu.Unlock()
						}
					}
				case <-ldapAliveEnd:
					ticker.Stop()

					return
				}
			}
		}(instance)
	}

	connectionCounter := 0

	for {
		select {
		case args = <-ldapRequestChan:
			go func(index int, args LdapRequest) {
				var (
					err    error
					ldapDN string
					result map[string][]string
				)

				ldapReply := LdapReply{}
				ldapReplyChan := args.replyChan

				if ldapInstance[index].Conn == nil || ldapInstance[index].isClosing() {
					level.Warn(logger).Log("instance", index+1, "msg", fmt.Sprintf("Connection #%d is closed", index+1))

					if ldapInstance[index].Conn != nil {
						ldapInstance[index].Conn.Close()
					}

					err = ldapInstance[index].connect(args.guid)
					if err != nil {
						ldapReply.err = err
						ldapReplyChan <- ldapReply

						return
					}

					err = ldapInstance[index].bind(args.guid)
					if err != nil {
						ldapReply.err = err
						ldapReplyChan <- ldapReply

						return
					}
				}

				if ldapDN, result, err = ldapInstance[index].search(
					args.guid, args.username, args.filter, args.attributes,
				); err != nil {
					level.Info(logger).Log("instance", index+1, "msg", err.Error())

					if !strings.Contains(err.Error(), "No Such Object") {
						if err != nil {
							ldapReply.err = err
							ldapReplyChan <- ldapReply

							return
						}
					}
				}

				ldapReply.err = nil
				ldapReply.dn = ldapDN
				ldapReply.result = result

				ldapReplyChan <- ldapReply
			}(connectionCounter, args)

		case <-ldapEnd:
			for instance := 0; instance < config.LDAP.PoolSize; instance++ {
				if ldapInstance[instance].Conn != nil {
					_ = ldapInstance[instance].unbind()
					ldapInstance[instance].Conn.Close()

					level.Debug(logger).Log("instance", instance+1, "msg", fmt.Sprintf("Connection #%d closed", instance+1))
				}
			}

			ldapAliveEnd <- true
			ldapEnd <- true

			break
		}

		connectionCounter++

		if connectionCounter == config.LDAP.PoolSize {
			connectionCounter = 0
		}
	}
}
