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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
)

const ldapSingleValue = 0

const distinguishedName = "dn"

type LdapConf struct {
	StartTLS      bool
	TLSSkipVerify bool
	SASLExternal  bool

	Scope int

	IdlePoolSize int
	PoolSize     int

	BaseDN        string
	BindDN        string
	BindPW        string
	Filter        string
	TLSCAFile     string
	TLSClientCert string
	TLSClientKey  string

	SearchAttributes []string

	ServerURIs []string
}

type LdapPool struct {
	ldapConnectionState

	Mu   sync.Mutex
	Conn *ldap.Conn
}

type LDAPCommand uint8

const (
	LDAPSearch LDAPCommand = iota
)

type LdapRequest struct {
	guid      *string
	username  string
	command   LDAPCommand
	replyChan chan *LdapReply
}

type DatabaseResult map[string][]any

type LdapReply struct {
	result DatabaseResult
	err    error
}

type LDAPState uint8

const (
	ldapStateClosed LDAPState = iota
	ldapStateFree   LDAPState = iota
	ldapStateBusy   LDAPState = iota
)

type ldapConnectionState struct {
	state LDAPState
}

func (l *LdapConf) String() string {
	var result string

	value := reflect.ValueOf(*l)
	typeOfValue := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfValue.Field(index).Name {
		case "BindPW":
			result += fmt.Sprintf(" %s='<hidden>'", typeOfValue.Field(index).Name)
		case "PoolSize", "IdlePoolSize":
			continue
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
		}
	}

	return result[1:]
}

func (l *LdapPool) isClosing() bool {
	return l.Conn.IsClosing()
}

func (l *LdapPool) connect(guid *string, ldapConf *LdapConf) error {
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

		if ldapCounter > len(ldapConf.ServerURIs)-1 {
			ldapCounter = 0
		}

		level.Debug(logger).Log(
			"guid", guid,
			"ldap_uri", ldapConf.ServerURIs[ldapCounter],
			"current_attempt", retryLimit+1,
			"max_attempt", ldapMaxRetries+1,
		)

		l.Conn, err = ldap.DialURL(ldapConf.ServerURIs[ldapCounter])
		if err != nil {
			ldapCounter++
			retryLimit++

			continue
		}

		if ldapConf.SASLExternal {
			// Certificates are not needed with ldapi//
			if ldapConf.TLSClientCert != "" && ldapConf.TLSClientKey != "" {
				cert, err := tls.LoadX509KeyPair(ldapConf.TLSClientCert, ldapConf.TLSClientKey)
				if err != nil {
					return err
				}

				certificates = []tls.Certificate{cert}
			}
		}

		if ldapConf.StartTLS {
			// Load CA chain
			caCert, err := os.ReadFile(ldapConf.TLSCAFile)
			if err != nil {
				return err
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			u, _ := url.Parse(ldapConf.ServerURIs[ldapCounter])

			host, _, err := net.SplitHostPort(u.Host)
			if err != nil {
				return err
			}

			tlsConfig := &tls.Config{
				Certificates:       certificates,
				RootCAs:            caCertPool,
				InsecureSkipVerify: ldapConf.TLSSkipVerify, //nolint:gosec // Support self-signed certificates
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

func (l *LdapPool) bind(guid *string, ldapConf *LdapConf) error {
	l.Mu.Lock()
	defer l.Mu.Unlock()

	var err error

	if ldapConf.SASLExternal {
		level.Debug(logger).Log("guid", guid, "msg", "SASL/EXTERNAL")

		err = l.Conn.ExternalBind()
		if err != nil {
			return err
		}

		if config.VerboseLevel >= logLevelDebug {
			res, err := l.Conn.WhoAmI(nil) //nolint:govet // Ignore
			if err == nil {
				level.Debug(logger).Log("guid", guid, "whoami", fmt.Sprintf("%+v", res))
			}
		}
	} else {
		level.Debug(logger).Log("guid", guid, "msg", "simple bind")
		level.Debug(logger).Log("guid", guid, "bind_dn", ldapConf.BindDN)

		_, err = l.Conn.SimpleBind(&ldap.SimpleBindRequest{
			Username: ldapConf.BindDN,
			Password: ldapConf.BindPW,
		})

		if err != nil {
			return err
		}

		if config.VerboseLevel >= logLevelDebug {
			res, err := l.Conn.WhoAmI(nil)
			if err == nil {
				level.Debug(logger).Log("guid", guid, "whoami", fmt.Sprintf("%+v", res))
			}
		}
	}

	return nil
}

func (l *LdapPool) unbind() (err error) {
	l.Mu.Lock()
	defer l.Mu.Unlock()

	err = l.Conn.Unbind()

	return
}

func (l *LdapPool) search(ldapConf LdapConf, ldapRequest *LdapRequest) (result DatabaseResult, err error) {
	var searchResult *ldap.SearchResult

	l.Mu.Lock()
	defer l.Mu.Unlock()

	ldapConf.Filter = strings.ReplaceAll(ldapConf.Filter, "%s", ldapRequest.username)

	re := regexp.MustCompile(`\s*[\r\n]+\s*`)
	ldapConf.Filter = re.ReplaceAllString(ldapConf.Filter, "")

	level.Debug(logger).Log("guid", ldapRequest.guid, "filter", ldapConf.Filter)

	searchRequest := ldap.NewSearchRequest(
		ldapConf.BaseDN,
		ldapConf.Scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		ldapConf.Filter,
		ldapConf.SearchAttributes,
		nil,
	)

	searchResult, err = l.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	result = make(DatabaseResult)

	for entryIndex := range searchResult.Entries {
		for attrIndex := range ldapConf.SearchAttributes {
			var anySlice []any

			values := searchResult.Entries[entryIndex].GetAttributeValues(ldapConf.SearchAttributes[attrIndex])

			// Do not add empty results
			if len(values) == 0 {
				continue
			}

			for index := range values {
				anySlice = append(anySlice, values[index])
			}

			if len(result[ldapConf.SearchAttributes[attrIndex]]) > 0 {
				result[ldapConf.SearchAttributes[attrIndex]] = append(result[ldapConf.SearchAttributes[attrIndex]], anySlice...)
			} else {
				result[ldapConf.SearchAttributes[attrIndex]] = anySlice
			}
		}

		if _, assertOk := result[distinguishedName]; assertOk {
			result[distinguishedName] = append(result[distinguishedName], searchResult.Entries[entryIndex].DN)
		} else {
			result[distinguishedName] = []any{searchResult.Entries[entryIndex].DN}
		}
	}

	return result, nil
}

func closeUnusedConnections(ctx context.Context, ldapPool []LdapPool) {
	// Cleanup interval
	timer := time.NewTicker(30 * time.Second) //nolint:gomnd // 30 seconds

	// Make (idle) pool size thread safe!
	poolSize := len(ldapPool)
	idlePoolSize := config.LdapConf.IdlePoolSize

	for {
		select {
		case <-ctx.Done():
			timer.Stop()
			level.Debug(logger).Log("msg", "closeUnusedConnections() terminated")

			return

		case <-timer.C:
			openConnections := 0

			for index := 0; index < poolSize; index++ {
				ldapPool[index].Mu.Lock()

				if ldapPool[index].state == ldapStateFree {
					if !(ldapPool[index].Conn == nil || ldapPool[index].Conn.IsClosing()) {
						_, err := ldapPool[index].Conn.Search(ldap.NewSearchRequest(
							"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30,
							false, "(objectClass=*)", []string{"1.1"}, nil,
						))

						if err != nil {
							// Lost connection
							level.Debug(logger).Log(
								"msg", fmt.Sprintf("LDAP free/busy state #%d has broken connection", index+1),
							)

							ldapPool[index].Conn = nil
							ldapPool[index].state = ldapStateClosed
						} else {
							openConnections++

							level.Debug(logger).Log(
								"msg", fmt.Sprintf("LDAP free/busy state #%d is free", index+1),
							)
						}
					} else {
						// Fix wrong state flag
						ldapPool[index].state = ldapStateClosed
					}
				} else {
					level.Debug(logger).Log(
						"msg", fmt.Sprintf("LDAP free/busy state #%d is busy or closed", index+1),
					)
				}

				ldapPool[index].Mu.Unlock()
			}

			for needClosing := openConnections - idlePoolSize; needClosing > 0; needClosing-- {
				for index := 0; index < poolSize; index++ {
					ldapPool[index].Mu.Lock()

					if ldapPool[index].state == ldapStateFree {
						ldapPool[index].Conn.Close()
						ldapPool[index].state = ldapStateClosed

						level.Debug(logger).Log(
							"msg", fmt.Sprintf("Connection #%d closed", index+1),
						)

						ldapPool[index].Mu.Unlock()

						break
					}

					ldapPool[index].Mu.Unlock()
				}
			}
		}
	}
}

//nolint:gocognit,maintidx // Ignore
func ldapWorker(ctx context.Context) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var (
		err           error
		ldapConnIndex int
		args          *LdapRequest
		ldapWaitGroup sync.WaitGroup
	)

	if config.LdapConf == nil {
		return
	}

	// Make (idle) pool size thread safe!
	poolSize := config.LdapConf.PoolSize
	idlePoolSize := config.LdapConf.IdlePoolSize

	ldapConf := make([]LdapConf, poolSize)
	ldapPool := make([]LdapPool, poolSize)

	for index := 0; index < poolSize; index++ {
		ldapConf[index].ServerURIs = config.LdapConf.ServerURIs
		ldapConf[index].BaseDN = config.LdapConf.BaseDN
		ldapConf[index].Filter = config.LdapConf.Filter
		ldapConf[index].SearchAttributes = config.LdapConf.SearchAttributes
		ldapConf[index].BindDN = config.LdapConf.BindDN
		ldapConf[index].BindPW = config.LdapConf.BindPW
		ldapConf[index].StartTLS = config.LdapConf.StartTLS
		ldapConf[index].TLSSkipVerify = config.LdapConf.TLSSkipVerify
		ldapConf[index].TLSCAFile = config.LdapConf.TLSCAFile
		ldapConf[index].TLSClientCert = config.LdapConf.TLSClientCert
		ldapConf[index].TLSClientKey = config.LdapConf.TLSClientKey
		ldapConf[index].SASLExternal = config.LdapConf.SASLExternal
		ldapConf[index].Scope = config.LdapConf.Scope

		ldapPool[index].state = ldapStateClosed
	}

	// Start background cleaner process
	go closeUnusedConnections(ctx, ldapPool)

	for {
		select {
		case <-ctx.Done():
			for i := 0; i < poolSize; i++ {
				if ldapPool[i].Conn != nil {
					_ = ldapPool[i].unbind()
					ldapPool[i].Conn.Close()

					level.Debug(logger).Log(
						"msg", fmt.Sprintf("Connection #%d closed", i+1),
					)
				}
			}

			level.Debug(logger).Log("msg", "ldapWorker() terminated")

			ldapEndChan <- true

			return

		case args = <-ldapRequestChan:
			ldapConnIndex = -1 // Reset connection index
			foundFreeConn := false
			openConnections := 0

			for index := 0; index < poolSize; index++ {
				if ldapPool[index].state != ldapStateClosed {
					openConnections++
				}
			}

			if openConnections < idlePoolSize {
				// Initialize the idle pool
				for index := openConnections; index < idlePoolSize; index++ {
					level.Debug(logger).Log("ldap", ldapConf[index].String())

					guidStr := fmt.Sprintf("pool-#%d", index+1)

					err = ldapPool[index].connect(&guidStr, &ldapConf[index])
					if err != nil {
						level.Error(logger).Log("error", err)
					} else {
						err = ldapPool[index].bind(&guidStr, &ldapConf[index])
						if err != nil {
							level.Error(logger).Log("error", err)
						}

						ldapPool[index].Mu.Lock()

						ldapPool[index].state = ldapStateFree

						ldapPool[index].Mu.Unlock()
					}
				}
			}

			for {
				for index := 0; index < poolSize; index++ {
					if ldapPool[index].state == ldapStateBusy {
						continue
					}

					if ldapPool[index].state == ldapStateFree {
						ldapPool[index].Mu.Lock()

						ldapPool[index].state = ldapStateBusy
						ldapConnIndex = index
						foundFreeConn = true

						ldapPool[index].Mu.Unlock()

						break
					}

					guidStr := fmt.Sprintf("pool-#%d", index+1)

					if ldapPool[index].state == ldapStateClosed {
						err = ldapPool[index].connect(&guidStr, &ldapConf[index])
						if err != nil {
							level.Error(logger).Log("error", err)
						} else {
							err = ldapPool[index].bind(&guidStr, &ldapConf[index])
							if err != nil {
								level.Error(logger).Log("error", err)
							}

							ldapPool[index].Mu.Lock()

							ldapPool[index].state = ldapStateFree

							ldapPool[index].Mu.Unlock()

							ldapConnIndex = index
							foundFreeConn = true
						}

						break
					}
				}

				// Pool exhausted, need to wait...
				if ldapConnIndex == -1 {
					ldapWaitGroup.Wait()
				}

				if foundFreeConn {
					break
				}
			}

			ldapWaitGroup.Add(1)

			go func(index int, ldapRequest *LdapRequest) {
				var (
					err    error
					result DatabaseResult
				)

				defer ldapWaitGroup.Done()

				ldapReply := &LdapReply{}
				ldapReplyChan := ldapRequest.replyChan

				if ldapPool[index].Conn == nil || ldapPool[index].isClosing() {
					level.Warn(logger).Log(
						"msg", fmt.Sprintf("Connection #%d is closed", index+1),
					)

					if ldapPool[index].Conn != nil {
						ldapPool[index].Conn.Close()
					}

					ldapPool[index].Mu.Lock()

					ldapPool[index].state = ldapStateClosed

					err = ldapPool[index].connect(ldapRequest.guid, &ldapConf[index])
					if err != nil {
						ldapReply.err = err
						ldapReplyChan <- ldapReply

						ldapPool[index].Mu.Unlock()

						return
					}

					err = ldapPool[index].bind(ldapRequest.guid, &ldapConf[index])
					if err != nil {
						ldapReply.err = err
						ldapReplyChan <- ldapReply

						ldapPool[index].Conn.Close()

						ldapPool[index].Mu.Unlock()

						return
					}

					ldapPool[index].state = ldapStateBusy

					ldapPool[index].Mu.Unlock()
				}

				if ldapRequest.command == LDAPSearch {
					if result, err = ldapPool[index].search(ldapConf[index], ldapRequest); err != nil {
						level.Info(logger).Log("msg", err)

						if !strings.Contains(err.Error(), "No Such Object") {
							if err != nil {
								ldapReply.err = err
								ldapReplyChan <- ldapReply

								ldapPool[index].Mu.Lock()

								ldapPool[index].state = ldapStateFree

								ldapPool[index].Mu.Unlock()

								return
							}
						}
					}
				}

				ldapPool[index].Mu.Lock()

				ldapPool[index].state = ldapStateFree

				ldapPool[index].Mu.Unlock()

				ldapReply.err = nil
				ldapReply.result = result

				ldapReplyChan <- ldapReply
			}(ldapConnIndex, args)
		}
	}
}
