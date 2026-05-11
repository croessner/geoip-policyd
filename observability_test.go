package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type recordedSpan struct {
	name    string
	traceID oteltrace.TraceID
	spanID  oteltrace.SpanID
	parent  oteltrace.SpanContext
	kind    oteltrace.SpanKind
}

type spanRecorder struct {
	mu    sync.Mutex
	spans []recordedSpan
}

// OnStart implements sdktrace.SpanProcessor without mutating started spans.
func (r *spanRecorder) OnStart(_ context.Context, _ sdktrace.ReadWriteSpan) {}

// OnEnd records immutable span identity and relationship fields for assertions.
func (r *spanRecorder) OnEnd(span sdktrace.ReadOnlySpan) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.spans = append(r.spans, recordedSpan{
		name:    span.Name(),
		traceID: span.SpanContext().TraceID(),
		spanID:  span.SpanContext().SpanID(),
		parent:  span.Parent(),
		kind:    span.SpanKind(),
	})
}

// Shutdown implements sdktrace.SpanProcessor.
func (r *spanRecorder) Shutdown(context.Context) error {
	return nil
}

// ForceFlush implements sdktrace.SpanProcessor.
func (r *spanRecorder) ForceFlush(context.Context) error {
	return nil
}

// findSpan returns the first recorded span with the supplied name.
func (r *spanRecorder) findSpan(name string) (recordedSpan, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, span := range r.spans {
		if span.name == name {
			return span, true
		}
	}

	return recordedSpan{}, false
}

// newTraceTestObservability returns an observability runtime backed by an in-memory span recorder.
func newTraceTestObservability(t *testing.T) (*Observability, *spanRecorder) {
	t.Helper()

	recorder := &spanRecorder{}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(recorder),
	)

	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
	})

	return &Observability{
		config: ObservabilityConfig{
			OTelEnabled:       true,
			OTelTracesEnabled: true,
		},
		tracer:        provider.Tracer(instrumentationName),
		traceProvider: provider,
	}, recorder
}

func TestObservabilityHTTPMiddlewareRecordsRequest(t *testing.T) {
	obs, err := NewObservability(
		t.Context(),
		ObservabilityConfig{
			PrometheusEnabled:        true,
			PrometheusRuntimeMetrics: false,
		},
		"test-version",
		log.NewNopLogger(),
	)
	if err != nil {
		t.Fatalf("NewObservability() error = %v", err)
	}

	handler := obs.InstrumentHTTP(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusAccepted)
	}))

	request := httptest.NewRequest(http.MethodPost, routeQuery, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if got := testutil.ToFloat64(obs.metrics.httpRequests.WithLabelValues(http.MethodPost, routeQuery, "2xx")); got != 1 {
		t.Fatalf("httpRequests = %v, want 1", got)
	}
}

func TestObservabilityHTTPMiddlewareLinksChildSpanToHTTPRequest(t *testing.T) {
	obs, recorder := newTraceTestObservability(t)

	handler := obs.InstrumentHTTP(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		_, span := obs.StartSpan(request.Context(), "handler.child")
		span.End()
		responseWriter.WriteHeader(http.StatusAccepted)
	}))

	request := httptest.NewRequest(http.MethodPost, routeQuery, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	httpSpan, ok := recorder.findSpan(httpSpanName(http.MethodPost, routeQuery))
	if !ok {
		t.Fatalf("HTTP span %q not recorded", httpSpanName(http.MethodPost, routeQuery))
	}

	if httpSpan.kind != oteltrace.SpanKindServer {
		t.Fatalf("HTTP span kind = %s, want server", httpSpan.kind)
	}

	childSpan, ok := recorder.findSpan("handler.child")
	if !ok {
		t.Fatal("handler child span not recorded")
	}

	if childSpan.traceID != httpSpan.traceID {
		t.Fatalf("child trace ID = %s, want %s", childSpan.traceID, httpSpan.traceID)
	}

	if childSpan.parent.SpanID() != httpSpan.spanID {
		t.Fatalf("child parent span ID = %s, want %s", childSpan.parent.SpanID(), httpSpan.spanID)
	}
}

func TestHTTPPostRemoveLinksRedisSpanToHTTPRequest(t *testing.T) {
	obs, recorder := newTraceTestObservability(t)
	client := newInstrumentedTestRedisClient(t, obs)
	installHTTPRedisTestGlobals(t, client)

	app := &HTTPApp{}
	handler := obs.InstrumentHTTP(http.HandlerFunc(app.httpRootPage))
	request := httptest.NewRequest(http.MethodPost, routeRemove, strings.NewReader(`{"key":"sender","value":"user@example.test"}`))
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("POST /remove status = %d, want %d", response.Code, http.StatusAccepted)
	}

	httpSpan, ok := recorder.findSpan(httpSpanName(http.MethodPost, routeRemove))
	if !ok {
		t.Fatalf("HTTP span %q not recorded", httpSpanName(http.MethodPost, routeRemove))
	}

	redisSpan, ok := recorder.findSpan(redisCommandSpanName("del"))
	if !ok {
		t.Fatalf("Redis span %q not recorded", redisCommandSpanName("del"))
	}

	if redisSpan.kind != oteltrace.SpanKindClient {
		t.Fatalf("Redis span kind = %s, want client", redisSpan.kind)
	}

	if redisSpan.traceID != httpSpan.traceID {
		t.Fatalf("Redis trace ID = %s, want %s", redisSpan.traceID, httpSpan.traceID)
	}

	if redisSpan.parent.SpanID() != httpSpan.spanID {
		t.Fatalf("Redis parent span ID = %s, want %s", redisSpan.parent.SpanID(), httpSpan.spanID)
	}
}

// newInstrumentedTestRedisClient returns an instrumented Redis client backed by the local fake RESP server.
func newInstrumentedTestRedisClient(t *testing.T, obs *Observability) *redis.Client {
	t.Helper()

	redisAddress, closeRedis := startTestRedisServer(t)
	t.Cleanup(closeRedis)

	client := redis.NewClient(&redis.Options{
		Addr:            redisAddress,
		Protocol:        2,
		DisableIdentity: true,
	})

	t.Cleanup(func() {
		_ = client.Close()
	})

	obs.InstrumentRedisClient(client, "primary")

	return client
}

// installHTTPRedisTestGlobals installs package-level dependencies used by HTTP handler tests.
func installHTTPRedisTestGlobals(t *testing.T, client redis.UniversalClient) {
	t.Helper()

	previousConfig := config
	previousRedisHandle := redisHandle
	previousLogger := logger

	t.Cleanup(func() {
		config = previousConfig
		redisHandle = previousRedisHandle
		logger = previousLogger
	})

	config = &CmdLineConfig{RedisPrefix: "trace_test_"}
	redisHandle = client
	logger = log.NewNopLogger()
}

// startTestRedisServer starts a minimal RESP server that accepts Redis DEL calls.
func startTestRedisServer(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	done := make(chan struct{})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}

			go handleTestRedisConnection(conn)
		}
	}()

	return listener.Addr().String(), func() {
		close(done)

		_ = listener.Close()
	}
}

// handleTestRedisConnection serves a small subset of Redis RESP replies.
func handleTestRedisConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		command, err := readTestRedisCommand(reader)
		if err != nil {
			return
		}

		if err := writeTestRedisResponse(writer, command); err != nil {
			return
		}
	}
}

// readTestRedisCommand reads one RESP array command from the fake Redis connection.
func readTestRedisCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(line, "*") {
		return nil, io.ErrUnexpectedEOF
	}

	commandCount, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil {
		return nil, err
	}

	command := make([]string, 0, commandCount)
	for range commandCount {
		lengthLine, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		if !strings.HasPrefix(lengthLine, "$") {
			return nil, io.ErrUnexpectedEOF
		}

		length, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(lengthLine, "$")))
		if err != nil {
			return nil, err
		}

		data := make([]byte, length+2)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}

		command = append(command, string(data[:length]))
	}

	return command, nil
}

// writeTestRedisResponse writes the minimal response needed by go-redis in these tests.
func writeTestRedisResponse(writer *bufio.Writer, command []string) error {
	if len(command) == 0 {
		_, err := writer.WriteString("-ERR empty command\r\n")
		if err != nil {
			return err
		}

		return writer.Flush()
	}

	switch strings.ToUpper(command[0]) {
	case "HELLO":
		_, _ = writer.WriteString("-ERR unknown command 'HELLO'\r\n")
	case "DEL":
		_, _ = writer.WriteString(":1\r\n")
	case "PING":
		_, _ = writer.WriteString("+PONG\r\n")
	default:
		_, _ = writer.WriteString("+OK\r\n")
	}

	return writer.Flush()
}

func TestNormalizeHTTPPathKeepsKnownRoutes(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "custom settings", path: routeCustomSettings, want: routeCustomSettings},
		{name: "dovecot policy", path: routeDovecotPolicy, want: routeDovecotPolicy},
		{name: "modify", path: routeModify, want: routeModify},
		{name: "query route", path: routeQuery, want: routeQuery},
		{name: "reload", path: routeReload, want: routeReload},
		{name: "remove", path: routeRemove, want: routeRemove},
		{name: "update", path: routeUpdate, want: routeUpdate},
		{name: "metrics", path: prometheusPath, want: prometheusPath},
		{name: "unknown", path: "/unknown/sender@example.test", want: routeOther},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeHTTPPath(test.path); got != test.want {
				t.Fatalf("normalizeHTTPPath(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

func TestObservabilityPolicyMetricsRecordOutcome(t *testing.T) {
	obs, err := NewObservability(
		t.Context(),
		ObservabilityConfig{
			PrometheusEnabled:        true,
			PrometheusRuntimeMetrics: false,
		},
		"test-version",
		log.NewNopLogger(),
	)
	if err != nil {
		t.Fatalf("NewObservability() error = %v", err)
	}

	obs.ObservePolicyRequest(t.Context(), sourceRestQuery, resultReject, 25*time.Millisecond)

	if got := testutil.ToFloat64(obs.metrics.policyRequests.WithLabelValues(sourceRestQuery, resultReject)); got != 1 {
		t.Fatalf("policyRequests = %v, want 1", got)
	}
}
