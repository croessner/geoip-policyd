// Package main provides an external OpenTelemetry and Prometheus smoke test for geoip-policyd.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	collectormetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

const (
	defaultAddress     = "8.8.8.8"
	defaultGeoIPPath   = "GeoIP2-Country.mmdb"
	defaultSender      = "otel-smoke@example.test"
	defaultTimeout     = 30 * time.Second
	geoIPLookupSpan    = "geoip.lookup"
	maxMindLookupSpan  = "geoip.maxmind.lookup"
	httpQuerySpanName  = "HTTP POST /query"
	loopbackAddress    = "127.0.0.1"
	metricPath         = "/metrics"
	otlpMetricPath     = "/v1/metrics"
	otlpTracePath      = "/v1/traces"
	policySpanName     = "policy.request"
	redisGetSpanName   = "redis.command GET"
	redisSetSpanName   = "redis.command SET"
	respCRLF           = "\r\n"
	smokeBinaryPattern = "geoip-policyd-smoke-*"
)

// smokeConfig contains operator-provided settings for the smoke run.
type smokeConfig struct {
	address  string
	binary   string
	geoIP    string
	repoRoot string
	sender   string
	timeout  time.Duration
}

// collectedSpan stores the exported span fields needed by topology assertions.
type collectedSpan struct {
	name         string
	traceID      string
	spanID       string
	parentSpanID string
	kind         tracepb.Span_SpanKind
}

// smokeRunner owns the end-to-end smoke workflow.
type smokeRunner struct {
	config *smokeConfig
	output io.Writer
}

// main parses flags, runs the smoke workflow, and exits non-zero on failure.
func main() {
	cfg, err := parseSmokeConfig(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)

		os.Exit(2)
	}

	runner := &smokeRunner{config: cfg, output: os.Stdout}
	if err := runner.Run(context.Background()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "smoke failed: %v\n", err)

		os.Exit(1)
	}
}

// parseSmokeConfig converts CLI flags into a validated smoke configuration.
func parseSmokeConfig(args []string) (*smokeConfig, error) {
	flags := flag.NewFlagSet("otel-prometheus-smoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	cfg := &smokeConfig{}
	flags.StringVar(&cfg.address, "address", defaultAddress, "client IP used by the policy request")
	flags.StringVar(&cfg.binary, "binary", "", "existing geoip-policyd binary; empty builds a temporary binary")
	flags.StringVar(&cfg.geoIP, "geoip-path", defaultGeoIPPath, "GeoIP database path relative to repo root")
	flags.StringVar(&cfg.repoRoot, "repo-root", ".", "geoip-policyd repository root")
	flags.StringVar(&cfg.sender, "sender", defaultSender, "sender used by the policy request")
	flags.DurationVar(&cfg.timeout, "timeout", defaultTimeout, "overall smoke timeout")

	if err := flags.Parse(args); err != nil {
		return nil, err
	}

	return cfg.normalize()
}

// normalize resolves filesystem paths and applies validation defaults.
func (c *smokeConfig) normalize() (*smokeConfig, error) {
	repoRoot, err := filepath.Abs(c.repoRoot)
	if err != nil {
		return nil, err
	}

	c.repoRoot = repoRoot
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}

	if c.binary != "" {
		c.binary, err = filepath.Abs(c.binary)
		if err != nil {
			return nil, err
		}
	}

	if !filepath.IsAbs(c.geoIP) {
		c.geoIP = filepath.Join(c.repoRoot, c.geoIP)
	}

	return c, nil
}

// Run executes the external server, OTLP, Redis, and Prometheus smoke test.
func (r *smokeRunner) Run(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, r.config.timeout)
	defer cancel()

	redisServer, err := startFakeRedisServer()
	if err != nil {
		return err
	}
	defer redisServer.Close()

	collector, err := startFakeOTLPCollector()
	if err != nil {
		return err
	}
	defer collector.Close(context.Background())

	service, err := r.startService(ctx, redisServer, collector)
	if err != nil {
		return err
	}
	defer service.Kill()

	if err = waitForPrometheus(ctx, service.httpBaseURL()); err != nil {
		return err
	}

	if err = sendPolicyQuery(ctx, service.httpBaseURL(), r.config.sender, r.config.address); err != nil {
		return err
	}

	prometheusBody, err := scrapePrometheus(ctx, service.httpBaseURL())
	if err != nil {
		return err
	}

	if err = service.Stop(ctx); err != nil {
		return err
	}

	return r.assertSmokeResults(collector, prometheusBody)
}

// startService builds or selects a binary and starts geoip-policyd as a child process.
func (r *smokeRunner) startService(ctx context.Context, redisServer *fakeRedisServer, collector *fakeOTLPCollector) (*serviceProcess, error) {
	binary, cleanup, err := r.resolveBinary(ctx)
	if err != nil {
		return nil, err
	}

	tcpPort, err := freeTCPPort()
	if err != nil {
		cleanup()
		return nil, err
	}

	httpPort, err := freeTCPPort()
	if err != nil {
		cleanup()
		return nil, err
	}

	process := newServiceProcess(r.config, binary, cleanup, tcpPort, httpPort)
	if err = process.Start(ctx, redisServer.Port(), collector.Endpoint()); err != nil {
		cleanup()
		return nil, err
	}

	return process, nil
}

// resolveBinary returns an existing binary or builds one into a temporary directory.
func (r *smokeRunner) resolveBinary(ctx context.Context) (string, func(), error) {
	if r.config.binary != "" {
		return r.config.binary, func() {}, nil
	}

	tmpDir, err := os.MkdirTemp("", smokeBinaryPattern)
	if err != nil {
		return "", func() {}, err
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}
	binary := filepath.Join(tmpDir, "geoip-policyd")
	command := exec.CommandContext(ctx, "go", "build", "-mod=vendor", "-trimpath", "-o", binary, ".")
	command.Dir = r.config.repoRoot

	output, err := command.CombinedOutput()
	if err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("building smoke binary: %w\n%s", err, string(output))
	}

	return binary, cleanup, nil
}

// assertSmokeResults checks both the Prometheus scrape and exported OTLP data.
func (r *smokeRunner) assertSmokeResults(collector *fakeOTLPCollector, prometheusBody string) error {
	if err := assertPrometheusMetrics(prometheusBody); err != nil {
		return err
	}

	if err := collector.AssertTraceTopology(); err != nil {
		return err
	}

	if err := collector.AssertOTelMetrics(); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(r.output, "prometheus metrics: http, policy, redis, geoip")
	_, _ = fmt.Fprintln(r.output, "otlp trace graph: HTTP POST /query -> policy.request -> geoip.lookup -> geoip.maxmind.lookup, redis.command GET, redis.command SET")
	_, _ = fmt.Fprintln(r.output, "otlp metrics: http, policy, redis, geoip")
	_, _ = fmt.Fprintln(r.output, "observability smoke passed")

	return nil
}

// serviceProcess owns the geoip-policyd subprocess and captured logs.
type serviceProcess struct {
	binary     string
	cleanup    func()
	command    *exec.Cmd
	config     *smokeConfig
	httpPort   int
	output     bytes.Buffer
	serverPort int
}

// newServiceProcess creates a service process wrapper for one smoke run.
func newServiceProcess(config *smokeConfig, binary string, cleanup func(), serverPort, httpPort int) *serviceProcess {
	return &serviceProcess{
		binary:     binary,
		cleanup:    cleanup,
		config:     config,
		httpPort:   httpPort,
		serverPort: serverPort,
	}
}

// Start launches the child service with isolated local Redis, OTLP, and HTTP ports.
func (p *serviceProcess) Start(ctx context.Context, redisPort int, otlpEndpoint string) error {
	args := p.args(redisPort, otlpEndpoint)
	p.command = exec.CommandContext(ctx, p.binary, args...)
	p.command.Dir = p.config.repoRoot
	p.command.Env = childEnvironment()
	p.command.Stdout = &p.output
	p.command.Stderr = &p.output

	if err := p.command.Start(); err != nil {
		return fmt.Errorf("starting geoip-policyd: %w", err)
	}

	return nil
}

// Stop asks the child service to flush observability and exit cleanly.
func (p *serviceProcess) Stop(ctx context.Context) error {
	if p.command == nil || p.command.Process == nil {
		return nil
	}

	if p.command.ProcessState != nil {
		return nil
	}

	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("signaling geoip-policyd: %w", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- p.command.Wait()
	}()

	select {
	case err := <-waitDone:
		return p.waitResult(err)
	case <-ctx.Done():
		_ = p.command.Process.Kill()
		return fmt.Errorf("stopping geoip-policyd: %w\n%s", ctx.Err(), p.output.String())
	}
}

// Kill forcefully cleans up a still-running child process.
func (p *serviceProcess) Kill() {
	if p.command != nil && p.command.Process != nil && p.command.ProcessState == nil {
		_ = p.command.Process.Kill()
		_, _ = p.command.Process.Wait()
	}

	p.cleanup()
}

// args returns the geoip-policyd server arguments used by the smoke test.
func (p *serviceProcess) args(redisPort int, otlpEndpoint string) []string {
	return []string{
		"server",
		"--server-address", loopbackAddress,
		"--server-port", strconv.Itoa(p.serverPort),
		"--http-address", loopbackAddress,
		"--http-port", strconv.Itoa(p.httpPort),
		"--redis-address", loopbackAddress,
		"--redis-port", strconv.Itoa(redisPort),
		"--redis-database-number", "1",
		"--redis-prefix", "otel_smoke_",
		"--geoip-path", p.config.geoIP,
		"--force-user-known",
		"--prometheus-enabled",
		"--otel-enabled",
		"--otel-traces-enabled",
		"--otel-metrics-enabled",
		"--otel-exporter-otlp-endpoint", otlpEndpoint,
		"--otel-exporter-otlp-insecure",
		"--otel-sample-ratio", "1.0",
	}
}

// httpBaseURL returns the REST service URL for this child process.
func (p *serviceProcess) httpBaseURL() string {
	return fmt.Sprintf("http://%s:%d", loopbackAddress, p.httpPort)
}

// waitResult normalizes child process exit errors with captured logs.
func (p *serviceProcess) waitResult(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("geoip-policyd exited with error: %w\n%s", err, p.output.String())
}

// childEnvironment returns the subprocess environment without test-only GeoIP suppression.
func childEnvironment() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))

	for _, item := range env {
		if strings.HasPrefix(item, "GO_TESTING=") {
			continue
		}

		filtered = append(filtered, item)
	}

	return filtered
}

// fakeOTLPCollector captures OTLP HTTP traces and metrics exported by the child process.
type fakeOTLPCollector struct {
	listener    net.Listener
	metricNames map[string]bool
	server      *http.Server
	spans       []collectedSpan
	mu          sync.Mutex
}

// startFakeOTLPCollector starts a local OTLP HTTP receiver.
func startFakeOTLPCollector() (*fakeOTLPCollector, error) {
	listener, err := net.Listen("tcp", loopbackAddress+":0")
	if err != nil {
		return nil, err
	}

	collector := &fakeOTLPCollector{
		listener:    listener,
		metricNames: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc(otlpTracePath, collector.handleTraces)
	mux.HandleFunc(otlpMetricPath, collector.handleMetrics)

	collector.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if serveErr := collector.server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			_, _ = fmt.Fprintf(os.Stderr, "OTLP smoke collector error: %v\n", serveErr)
		}
	}()

	return collector, nil
}

// Endpoint returns the host:port OTLP endpoint configured in geoip-policyd.
func (c *fakeOTLPCollector) Endpoint() string {
	return c.listener.Addr().String()
}

// Close stops the fake OTLP HTTP receiver.
func (c *fakeOTLPCollector) Close(ctx context.Context) {
	if c.server != nil {
		_ = c.server.Shutdown(ctx)
	}
}

// AssertTraceTopology verifies the exported trace graph expected from POST /query.
func (c *fakeOTLPCollector) AssertTraceTopology() error {
	spans := c.spanMap()
	required := []string{httpQuerySpanName, policySpanName, geoIPLookupSpan, maxMindLookupSpan, redisGetSpanName, redisSetSpanName}

	for _, name := range required {
		if _, ok := spans[name]; !ok {
			return fmt.Errorf("missing OTLP span %q; got %s", name, c.spanNames())
		}
	}

	return assertSpanRelationships(spans)
}

// AssertOTelMetrics verifies that OTLP metrics were exported at shutdown.
func (c *fakeOTLPCollector) AssertOTelMetrics() error {
	required := []string{
		"geoip_policyd_http_requests",
		"geoip_policyd_policy_requests",
		"geoip_policyd_redis_operations",
		"geoip_policyd_geoip_lookups",
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, name := range required {
		if !c.metricNames[name] {
			return fmt.Errorf("missing OTLP metric %q", name)
		}
	}

	return nil
}

// handleTraces decodes one OTLP trace export request.
func (c *fakeOTLPCollector) handleTraces(response http.ResponseWriter, request *http.Request) {
	exportRequest := &collectortracepb.ExportTraceServiceRequest{}
	if !decodeProtoRequest(response, request, exportRequest) {
		return
	}

	c.recordTraceSpans(exportRequest)
	writeProtoResponse(response, &collectortracepb.ExportTraceServiceResponse{})
}

// handleMetrics decodes one OTLP metric export request.
func (c *fakeOTLPCollector) handleMetrics(response http.ResponseWriter, request *http.Request) {
	exportRequest := &collectormetricpb.ExportMetricsServiceRequest{}
	if !decodeProtoRequest(response, request, exportRequest) {
		return
	}

	c.recordMetricNames(exportRequest)
	writeProtoResponse(response, &collectormetricpb.ExportMetricsServiceResponse{})
}

// recordTraceSpans appends all spans contained in an OTLP trace export request.
func (c *fakeOTLPCollector) recordTraceSpans(request *collectortracepb.ExportTraceServiceRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, resourceSpans := range request.ResourceSpans {
		for _, scopeSpans := range resourceSpans.ScopeSpans {
			for _, span := range scopeSpans.Spans {
				c.spans = append(c.spans, collectedSpan{
					name:         span.Name,
					traceID:      hex.EncodeToString(span.TraceId),
					spanID:       hex.EncodeToString(span.SpanId),
					parentSpanID: hex.EncodeToString(span.ParentSpanId),
					kind:         span.Kind,
				})
			}
		}
	}
}

// recordMetricNames stores all metric names contained in an OTLP metric export request.
func (c *fakeOTLPCollector) recordMetricNames(request *collectormetricpb.ExportMetricsServiceRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, resourceMetrics := range request.ResourceMetrics {
		for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
			for _, metric := range scopeMetrics.Metrics {
				c.metricNames[metric.Name] = true
			}
		}
	}
}

// spanMap returns the first span by name from the collected exports.
func (c *fakeOTLPCollector) spanMap() map[string]collectedSpan {
	c.mu.Lock()
	defer c.mu.Unlock()

	spans := make(map[string]collectedSpan, len(c.spans))
	for _, span := range c.spans {
		if _, exists := spans[span.name]; !exists {
			spans[span.name] = span
		}
	}

	return spans
}

// spanNames returns a printable set of collected span names.
func (c *fakeOTLPCollector) spanNames() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	names := make([]string, 0, len(c.spans))
	for _, span := range c.spans {
		names = append(names, span.name)
	}

	return strings.Join(names, ", ")
}

// assertSpanRelationships validates the parent-child graph exported for one query.
func assertSpanRelationships(spans map[string]collectedSpan) error {
	httpSpan := spans[httpQuerySpanName]
	policySpan := spans[policySpanName]
	geoIPSpan := spans[geoIPLookupSpan]
	maxMindSpan := spans[maxMindLookupSpan]
	redisGETSpan := spans[redisGetSpanName]
	redisSETSpan := spans[redisSetSpanName]

	if httpSpan.kind != tracepb.Span_SPAN_KIND_SERVER {
		return fmt.Errorf("%q kind = %s, want SERVER", httpSpan.name, httpSpan.kind)
	}

	if policySpan.parentSpanID != httpSpan.spanID {
		return fmt.Errorf("policy parent = %s, want HTTP span %s", policySpan.parentSpanID, httpSpan.spanID)
	}

	if err := assertPolicyChildren(policySpan, geoIPSpan, redisGETSpan, redisSETSpan); err != nil {
		return err
	}

	return assertTraceChild(geoIPSpan, maxMindSpan)
}

// assertPolicyChildren validates all expected child spans under policy.request.
func assertPolicyChildren(policySpan, geoIPSpan, redisGETSpan, redisSETSpan collectedSpan) error {
	children := []collectedSpan{geoIPSpan, redisGETSpan, redisSETSpan}
	for _, child := range children {
		if child.traceID != policySpan.traceID {
			return fmt.Errorf("%q trace = %s, want %s", child.name, child.traceID, policySpan.traceID)
		}

		if child.parentSpanID != policySpan.spanID {
			return fmt.Errorf("%q parent = %s, want policy span %s", child.name, child.parentSpanID, policySpan.spanID)
		}
	}

	if redisGETSpan.kind != tracepb.Span_SPAN_KIND_CLIENT || redisSETSpan.kind != tracepb.Span_SPAN_KIND_CLIENT {
		return fmt.Errorf("redis spans are not client spans")
	}

	return nil
}

// assertTraceChild verifies that a span is a direct child of another span in the same trace.
func assertTraceChild(parent, child collectedSpan) error {
	if child.traceID != parent.traceID {
		return fmt.Errorf("%q trace = %s, want %s", child.name, child.traceID, parent.traceID)
	}

	if child.parentSpanID != parent.spanID {
		return fmt.Errorf("%q parent = %s, want span %s", child.name, child.parentSpanID, parent.spanID)
	}

	return nil
}

// fakeRedisServer implements the minimal Redis RESP commands needed by the smoke test.
type fakeRedisServer struct {
	listener net.Listener
	store    map[string]string
	mu       sync.Mutex
}

// startFakeRedisServer starts a local fake Redis server.
func startFakeRedisServer() (*fakeRedisServer, error) {
	listener, err := net.Listen("tcp", loopbackAddress+":0")
	if err != nil {
		return nil, err
	}

	server := &fakeRedisServer{listener: listener, store: map[string]string{}}
	go server.acceptLoop()

	return server, nil
}

// Port returns the TCP port used by the fake Redis server.
func (s *fakeRedisServer) Port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

// Close stops the fake Redis server.
func (s *fakeRedisServer) Close() {
	_ = s.listener.Close()
}

// acceptLoop accepts fake Redis connections until the listener is closed.
func (s *fakeRedisServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		go s.handleConnection(conn)
	}
}

// handleConnection processes RESP commands for one fake Redis client.
func (s *fakeRedisServer) handleConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		command, err := readRESPCommand(reader)
		if err != nil {
			return
		}

		if err = s.writeResponse(writer, command); err != nil {
			return
		}
	}
}

// writeResponse writes a fake Redis response for a parsed command.
func (s *fakeRedisServer) writeResponse(writer *bufio.Writer, command []string) error {
	if len(command) == 0 {
		return writeSimpleError(writer, "empty command")
	}

	switch strings.ToUpper(command[0]) {
	case "CLIENT", "SELECT":
		return writeSimpleString(writer, "OK")
	case "DEL":
		return s.writeDelete(writer, command)
	case "EXPIRE":
		return s.writeExpire(writer, command)
	case "GET":
		return s.writeGet(writer, command)
	case "HELLO":
		return writeSimpleError(writer, "unknown command 'HELLO'")
	case "PING":
		return writeSimpleString(writer, "PONG")
	case "SET":
		return s.writeSet(writer, command)
	default:
		return writeSimpleString(writer, "OK")
	}
}

// writeGet returns a bulk string or nil response from the fake Redis store.
func (s *fakeRedisServer) writeGet(writer *bufio.Writer, command []string) error {
	if len(command) < 2 {
		return writeSimpleError(writer, "wrong number of arguments for GET")
	}

	s.mu.Lock()
	value, ok := s.store[command[1]]
	s.mu.Unlock()

	if !ok {
		return writeRaw(writer, "$-1"+respCRLF)
	}

	return writeRaw(writer, fmt.Sprintf("$%d%s%s%s", len(value), respCRLF, value, respCRLF))
}

// writeSet stores a value in the fake Redis store.
func (s *fakeRedisServer) writeSet(writer *bufio.Writer, command []string) error {
	if len(command) < 3 {
		return writeSimpleError(writer, "wrong number of arguments for SET")
	}

	s.mu.Lock()
	s.store[command[1]] = command[2]
	s.mu.Unlock()

	return writeSimpleString(writer, "OK")
}

// writeDelete deletes a key from the fake Redis store.
func (s *fakeRedisServer) writeDelete(writer *bufio.Writer, command []string) error {
	if len(command) < 2 {
		return writeInteger(writer, 0)
	}

	s.mu.Lock()
	_, existed := s.store[command[1]]
	delete(s.store, command[1])
	s.mu.Unlock()

	if existed {
		return writeInteger(writer, 1)
	}

	return writeInteger(writer, 0)
}

// writeExpire handles immediate expiration used when Redis TTL is disabled.
func (s *fakeRedisServer) writeExpire(writer *bufio.Writer, command []string) error {
	if len(command) >= 3 && command[2] == "0" {
		s.mu.Lock()
		delete(s.store, command[1])
		s.mu.Unlock()
	}

	return writeInteger(writer, 1)
}

// readRESPCommand parses one Redis RESP array command.
func readRESPCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected RESP array, got %q", strings.TrimSpace(line))
	}

	count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil {
		return nil, err
	}

	return readRESPBulkStrings(reader, count)
}

// readRESPBulkStrings reads the bulk string arguments for one RESP command.
func readRESPBulkStrings(reader *bufio.Reader, count int) ([]string, error) {
	command := make([]string, 0, count)

	for range count {
		length, err := readBulkLength(reader)
		if err != nil {
			return nil, err
		}

		data := make([]byte, length+2)
		if _, err = io.ReadFull(reader, data); err != nil {
			return nil, err
		}

		command = append(command, string(data[:length]))
	}

	return command, nil
}

// readBulkLength reads one RESP bulk-string length header.
func readBulkLength(reader *bufio.Reader) (int, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	if !strings.HasPrefix(line, "$") {
		return 0, fmt.Errorf("expected RESP bulk string, got %q", strings.TrimSpace(line))
	}

	return strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "$")))
}

// writeSimpleString writes a Redis simple-string response.
func writeSimpleString(writer *bufio.Writer, value string) error {
	return writeRaw(writer, "+"+value+respCRLF)
}

// writeSimpleError writes a Redis error response.
func writeSimpleError(writer *bufio.Writer, value string) error {
	return writeRaw(writer, "-ERR "+value+respCRLF)
}

// writeInteger writes a Redis integer response.
func writeInteger(writer *bufio.Writer, value int) error {
	return writeRaw(writer, fmt.Sprintf(":%d%s", value, respCRLF))
}

// writeRaw writes and flushes one raw RESP response.
func writeRaw(writer *bufio.Writer, value string) error {
	if _, err := writer.WriteString(value); err != nil {
		return err
	}

	return writer.Flush()
}

// waitForPrometheus waits until the HTTP service exposes its metrics endpoint.
func waitForPrometheus(ctx context.Context, baseURL string) error {
	return waitUntil(ctx, func() bool {
		response, err := http.Get(baseURL + metricPath)
		if err != nil {
			return false
		}
		defer closeIgnoringError(response.Body)

		return response.StatusCode == http.StatusOK
	})
}

// sendPolicyQuery sends the external POST /query request used by the smoke test.
func sendPolicyQuery(ctx context.Context, baseURL, sender, address string) error {
	payload := map[string]any{"key": "client", "value": map[string]string{"address": address, "sender": sender}}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/query", bytes.NewReader(body))
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer closeIgnoringError(response.Body)

	if response.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(response.Body)
		return fmt.Errorf("POST /query status = %d: %s", response.StatusCode, string(data))
	}

	return nil
}

// scrapePrometheus reads the Prometheus metrics endpoint after the smoke request.
func scrapePrometheus(ctx context.Context, baseURL string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+metricPath, nil)
	if err != nil {
		return "", err
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	defer closeIgnoringError(response.Body)

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// assertPrometheusMetrics verifies the scrape contains request, policy, Redis, and GeoIP metrics.
func assertPrometheusMetrics(body string) error {
	required := []string{
		`geoip_policyd_http_requests_total{method="POST",path="/query",status_class="2xx"}`,
		`geoip_policyd_policy_requests_total{outcome=`,
		`source="rest_query"`,
		`geoip_policyd_redis_operations_total{operation="get"`,
		`geoip_policyd_redis_operations_total{operation="set"`,
		`geoip_policyd_geoip_lookups_total{result=`,
	}

	for _, fragment := range required {
		if !strings.Contains(body, fragment) {
			return fmt.Errorf("prometheus scrape missing %q", fragment)
		}
	}

	return nil
}

// waitUntil polls a condition until it succeeds or the context expires.
func waitUntil(ctx context.Context, condition func() bool) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// freeTCPPort asks the kernel for a currently free local TCP port.
func freeTCPPort() (int, error) {
	listener, err := net.Listen("tcp", loopbackAddress+":0")
	if err != nil {
		return 0, err
	}
	defer closeIgnoringError(listener)

	return listener.Addr().(*net.TCPAddr).Port, nil
}

// readRequestBody reads an OTLP request body with optional gzip decoding.
func readRequestBody(request *http.Request) ([]byte, error) {
	reader := request.Body
	if request.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(request.Body)
		if err != nil {
			return nil, err
		}
		defer closeIgnoringError(gzipReader)

		reader = gzipReader
	}

	defer closeIgnoringError(request.Body)

	return io.ReadAll(reader)
}

// decodeProtoRequest reads and unmarshals an OTLP HTTP protobuf request.
func decodeProtoRequest(response http.ResponseWriter, request *http.Request, message proto.Message) bool {
	body, err := readRequestBody(request)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return false
	}

	if err = proto.Unmarshal(body, message); err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return false
	}

	return true
}

// closeIgnoringError closes resources in cleanup paths where callers cannot act on close errors.
func closeIgnoringError(closer io.Closer) {
	_ = closer.Close()
}

// writeProtoResponse writes a protobuf OTLP response.
func writeProtoResponse(response http.ResponseWriter, message proto.Message) {
	data, err := proto.Marshal(message)
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}

	response.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = response.Write(data)
}
