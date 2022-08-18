package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MaxConnections   = 100
	TotalConnections = 100000
)

const (
	ALL   = "all"
	TEST1 = "test1"
	TEST2 = "test2"
)

type SimultaneousConnections struct {
	mu      sync.Mutex
	current int32
}

//nolint:gocognit,gocyclo,forbidigo,maintidx,gomnd,forcetypeassert // This is a q&d stress test...
func main() {
	if len(os.Args) < 5 || len(os.Args) > 6 {
		fmt.Println("Required args: <host:port> <sender> <client_address> <Total number of tests> [optional test]")

		os.Exit(1)
	}

	counter := make(chan int, MaxConnections)
	exit := make(chan int)
	host := os.Args[1]
	sender := os.Args[2]
	clientAddress := os.Args[3]
	totalConnections, _ := strconv.Atoi(os.Args[4])

	if totalConnections < MaxConnections {
		totalConnections = TotalConnections
	}

	var test string

	if len(os.Args) == 6 {
		switch os.Args[5] {
		case TEST1:
			test = TEST1
		case TEST2:
			test = TEST2
		default:
			test = ALL
		}
	} else {
		test = ALL
	}

	var (
		failed         atomic.Value
		failedConnect  atomic.Value
		failedDeadline atomic.Value
		failedRead     atomic.Value
		failedWrite    atomic.Value
	)

	msg := fmt.Sprintf("request=smtpd_access_policy\nsender=%s\nsasl_username=%s\nclient_address=%s\n\n",
		sender, sender, clientAddress)

	/*
	 * Test 1
	 */
	if test == ALL || test == TEST1 {
		fmt.Printf("Testing 1 request per connection, %d parallel\n", MaxConnections)

		numberOfConnections := &SimultaneousConnections{current: 0}

		failed.Store(0)
		failedConnect.Store(0)
		failedDeadline.Store(0)
		failedRead.Store(0)
		failedWrite.Store(0)

		start := time.Now()

		for connectionCounter := 0; connectionCounter < totalConnections; connectionCounter++ {
			counter <- connectionCounter

			go func() {
				numberOfConnections.mu.Lock()

				numberOfConnections.current++

				numberOfConnections.mu.Unlock()

				var (
					conn   net.Conn
					err    error
					line   string
					cycles int
				)

				timeoutDuration := time.Second * 30

				if conn, err = net.Dial("tcp", host); err != nil {
					failed.Store(failed.Load().(int) + 1)
					failedConnect.Store(failedConnect.Load().(int) + 1)

					goto abort
				}

				//goland:noinspection GoUnhandledErrorResult
				defer conn.Close()

				err = conn.SetDeadline(time.Now().Add(timeoutDuration))
				if err != nil {
					failed.Store(failed.Load().(int) + 1)
					failedDeadline.Store(failedDeadline.Load().(int) + 1)

					goto abort
				}

				_, err = conn.Write([]byte(msg))
				if err != nil {
					failed.Store(failed.Load().(int) + 1)
					failedWrite.Store(failedWrite.Load().(int) + 1)

					goto abort
				}

				cycles = 0

				for {
					buffer := make([]byte, 1024)
					// Read action= string
					_, err = conn.Read(buffer)

					if err != nil {
						failed.Store(failed.Load().(int) + 1)
						failedRead.Store(failedRead.Load().(int) + 1)

						goto abort
					}

					line = strings.TrimSpace(string(buffer))
					if strings.HasPrefix(line, "action=") {
						break
					}

					time.Sleep(time.Millisecond)

					if cycles > 5000 {
						failed.Store(failed.Load().(int) + 1)
						failedRead.Store(failedRead.Load().(int) + 1)

						break
					}
				}

			abort:

				numberOfConnections.mu.Lock()

				number := numberOfConnections.current
				numberOfConnections.current--

				numberOfConnections.mu.Unlock()

				absolut := <-counter

				absolut++

				fmt.Printf("\rCurrent connections: %3d total: %d%%", number, 100*absolut/totalConnections)

				if absolut == totalConnections {
					exit <- 0
				}
			}()
		}

		<-exit

		elapsed := time.Since(start)
		connectionsPerSecond := int(float64(totalConnections) / elapsed.Seconds())

		fmt.Printf("\nFailed number of requests: %d (%d%%), total time: %.0fs, connections per second: %d\n",
			failed.Load().(int), 100*failed.Load().(int)/totalConnections, elapsed.Seconds(), connectionsPerSecond)
		fmt.Printf("Absolute failures: connect: %d, deadline: %d, read: %d, write: %d\n",
			failedConnect.Load().(int), failedDeadline.Load().(int), failedRead.Load().(int), failedWrite.Load().(int))
	}

	/*
	 * Test 2
	 */
	if test == ALL || test == TEST2 {
		requestsPerConnection := totalConnections / MaxConnections

		fmt.Printf("Testing %d requests per connection, %d parallel\n", requestsPerConnection, MaxConnections)

		numberOfConnections := &SimultaneousConnections{current: 0}

		failed.Store(0)
		failedConnect.Store(0)
		failedDeadline.Store(0)
		failedRead.Store(0)
		failedWrite.Store(0)

		start := time.Now()

		waitGroup := sync.WaitGroup{}

		stats := make(chan int32)
		statsEnd := make(chan int)

		go func() {
			for {
				select {
				case c := <-stats:
					fmt.Printf("\rRequest: %d total: %d%%", c, 100*int(c)/totalConnections)
				case <-statsEnd:
					return
				}
			}
		}()

		for connection := 0; connection < MaxConnections; connection++ {
			waitGroup.Add(1)

			go func() {
				var (
					conn   net.Conn
					err    error
					line   string
					cycles int
				)

				timeoutDuration := time.Second * 900 // Safety net 15 minutes timeout
				requestCounter := 0

				if conn, err = net.Dial("tcp", host); err != nil {
					failed.Store(failed.Load().(int) + 1)
					failedConnect.Store(failedConnect.Load().(int) + 1)

					goto abort
				}

				//goland:noinspection GoUnhandledErrorResult
				defer conn.Close()

				err = conn.SetDeadline(time.Now().Add(timeoutDuration))
				if err != nil {
					failed.Store(failed.Load().(int) + 1)
					failedDeadline.Store(failedDeadline.Load().(int) + 1)

					goto abort
				}

				for ; requestCounter < requestsPerConnection; requestCounter++ {
					_, err = conn.Write([]byte(msg))
					if err != nil {
						failedWrite.Store(failedWrite.Load().(int) + 1)

						goto abort
					}

					cycles = 0

					for {
						buffer := make([]byte, 1024)

						// Read action= string
						_, err = conn.Read(buffer)
						if err != nil {
							fmt.Println(err.Error())
							failedRead.Store(failedRead.Load().(int) + 1)

							goto abort
						}

						line = strings.TrimSpace(string(buffer))
						if strings.HasPrefix(line, "action=") {
							break
						}

						time.Sleep(time.Millisecond)

						if cycles > 5000 {
							failedRead.Store(failedRead.Load().(int) + 1)

							break
						}
					}

					numberOfConnections.mu.Lock()

					numberOfConnections.current++
					number := numberOfConnections.current

					numberOfConnections.mu.Unlock()

					stats <- number
				}

			abort:

				failed.Store(failed.Load().(int) + (requestsPerConnection - requestCounter))
				waitGroup.Done()
			}()
		}

		waitGroup.Wait()
		statsEnd <- 0

		elapsed := time.Since(start)
		requestsPerSecond := int(float64(totalConnections) / elapsed.Seconds())

		fmt.Printf("\nFailed number of requests: %d (%d%%), total time: %.0fs, requests per second: %d\n",
			failed.Load().(int), 100*failed.Load().(int)/totalConnections, elapsed.Seconds(), requestsPerSecond)
		fmt.Printf("Absolute failures: connect: %d, deadline: %d, read: %d, write: %d\n",
			failedConnect.Load().(int), failedDeadline.Load().(int), failedRead.Load().(int), failedWrite.Load().(int))
	}
}
