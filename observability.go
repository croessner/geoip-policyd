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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	instrumentationName = "geoip-policyd"

	labelAction      = "action"
	labelEvent       = "event"
	labelMethod      = "method"
	labelOperation   = "operation"
	labelOutcome     = "outcome"
	labelPath        = "path"
	labelResult      = "result"
	labelRole        = "role"
	labelSource      = "source"
	labelStatusClass = "status_class"
	labelState       = "state"

	eventAccept = "accept"
	eventClose  = "close"

	operationRedisDial     = "dial"
	operationRedisPipeline = "pipeline"

	resultEmpty       = "empty"
	resultError       = "error"
	resultFound       = "found"
	resultHit         = "hit"
	resultInfo        = "info"
	resultInvalid     = "invalid"
	resultMiss        = "miss"
	resultNotFound    = "not_found"
	resultOK          = "ok"
	resultAccept      = "accept"
	resultReject      = "reject"
	resultStatError   = "stat_error"
	resultUnavailable = "unavailable"
	resultUnknown     = "unknown"
	resultWhitelist   = "whitelist"

	routeCustomSettings = "/custom-settings"
	routeDovecotPolicy  = "/dovecotpolicy"
	routeModify         = "/modify"
	routeQuery          = "/query"
	routeReload         = "/reload"
	routeRemove         = "/remove"
	routeUpdate         = "/update"
	routeOther          = "other"

	sourceDovecot    = "dovecot"
	sourcePostfixTCP = "postfix_tcp"
	sourceRestQuery  = "rest_query"
)

// Observability owns Prometheus collectors and OpenTelemetry providers for the process.
type Observability struct {
	config ObservabilityConfig
	logger log.Logger

	registry *prometheus.Registry
	metrics  *prometheusMetrics

	tracer        trace.Tracer
	meter         metric.Meter
	traceProvider *sdktrace.TracerProvider
	meterProvider *sdkmetric.MeterProvider
	otelMetrics   *otelMetricInstruments
}

// prometheusMetrics groups all Prometheus collectors owned by this process.
type prometheusMetrics struct {
	httpRequests        *prometheus.CounterVec
	httpDuration        *prometheus.HistogramVec
	policyRequests      *prometheus.CounterVec
	policyDuration      *prometheus.HistogramVec
	redisOperations     *prometheus.CounterVec
	redisDuration       *prometheus.HistogramVec
	ldapOperations      *prometheus.CounterVec
	ldapDuration        *prometheus.HistogramVec
	ldapPoolConnections *prometheus.GaugeVec
	geoIPLookups        *prometheus.CounterVec
	geoIPLookupDuration *prometheus.HistogramVec
	geoIPReloads        *prometheus.CounterVec
	cdbLookups          *prometheus.CounterVec
	cdbDuration         *prometheus.HistogramVec
	actions             *prometheus.CounterVec
	actionDuration      *prometheus.HistogramVec
	tcpConnections      *prometheus.CounterVec
	tcpActive           prometheus.Gauge
}

// otelMetricInstruments mirrors key Prometheus signals to an OTLP metrics exporter.
type otelMetricInstruments struct {
	httpRequests        metric.Int64Counter
	httpDuration        metric.Float64Histogram
	policyRequests      metric.Int64Counter
	policyDuration      metric.Float64Histogram
	redisOperations     metric.Int64Counter
	redisDuration       metric.Float64Histogram
	ldapOperations      metric.Int64Counter
	ldapDuration        metric.Float64Histogram
	geoIPLookups        metric.Int64Counter
	geoIPLookupDuration metric.Float64Histogram
	geoIPReloads        metric.Int64Counter
	cdbLookups          metric.Int64Counter
	cdbDuration         metric.Float64Histogram
	actions             metric.Int64Counter
	actionDuration      metric.Float64Histogram
	tcpConnections      metric.Int64Counter
	tcpActive           metric.Int64UpDownCounter
}

// NewObservability initializes enabled Prometheus and OpenTelemetry components.
func NewObservability(ctx context.Context, cfg ObservabilityConfig, serviceVersion string, logger log.Logger) (*Observability, error) {
	cfg = normalizeObservabilityConfig(cfg, serviceVersion)

	obs := &Observability{
		config: cfg,
		logger: logger,
		tracer: otel.Tracer(instrumentationName),
		meter:  otel.Meter(instrumentationName),
	}

	if cfg.PrometheusEnabled {
		obs.registry = prometheus.NewRegistry()
		obs.metrics = newPrometheusMetrics(obs.registry, cfg.PrometheusRuntimeMetrics)
	}

	if cfg.OTelEnabled {
		if err := obs.initializeOpenTelemetry(ctx); err != nil {
			return nil, err
		}
	}

	return obs, nil
}

// normalizeObservabilityConfig applies runtime defaults that are awkward to express through zero values.
func normalizeObservabilityConfig(cfg ObservabilityConfig, serviceVersion string) ObservabilityConfig {
	if cfg.PrometheusPath == "" {
		cfg.PrometheusPath = prometheusPath
	}

	if cfg.OTelServiceName == "" {
		cfg.OTelServiceName = otelService
	}

	if cfg.OTelServiceVersion == "" {
		cfg.OTelServiceVersion = serviceVersion
	}

	if cfg.OTLPHeaders == nil {
		cfg.OTLPHeaders = make(map[string]string)
	}

	return cfg
}

// initializeOpenTelemetry configures OTLP HTTP tracing and metrics exporters.
func (o *Observability) initializeOpenTelemetry(ctx context.Context) error {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", o.config.OTelServiceName),
			attribute.String("service.version", o.config.OTelServiceVersion),
		),
	)
	if err != nil {
		return fmt.Errorf("creating OpenTelemetry resource: %w", err)
	}

	if o.config.OTelTracesEnabled {
		if err = o.initializeOpenTelemetryTracing(ctx, res); err != nil {
			return err
		}
	}

	if o.config.OTelMetricsEnabled {
		if err = o.initializeOpenTelemetryMetrics(ctx, res); err != nil {
			return err
		}
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})

	return nil
}

// initializeOpenTelemetryTracing starts a batch trace provider backed by OTLP HTTP.
func (o *Observability) initializeOpenTelemetryTracing(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlptracehttp.New(ctx, traceHTTPOptions(o.config)...)
	if err != nil {
		return fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(o.config.OTelSampleRatio))
	o.traceProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
		sdktrace.WithBatcher(exporter),
	)
	o.tracer = o.traceProvider.Tracer(instrumentationName)
	otel.SetTracerProvider(o.traceProvider)

	return nil
}

// initializeOpenTelemetryMetrics starts a periodic OTLP HTTP metric reader.
func (o *Observability) initializeOpenTelemetryMetrics(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlpmetrichttp.New(ctx, metricHTTPOptions(o.config)...)
	if err != nil {
		return fmt.Errorf("creating OTLP metric exporter: %w", err)
	}

	o.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
	)
	o.meter = o.meterProvider.Meter(instrumentationName)
	otel.SetMeterProvider(o.meterProvider)

	return o.initializeOpenTelemetryInstruments()
}

// traceHTTPOptions converts the local config into OTLP trace HTTP exporter options.
func traceHTTPOptions(cfg ObservabilityConfig) []otlptracehttp.Option {
	endpoint, insecure := normalizedOTLPEndpoint(cfg)

	options := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if insecure {
		options = append(options, otlptracehttp.WithInsecure())
	}

	if len(cfg.OTLPHeaders) > 0 {
		options = append(options, otlptracehttp.WithHeaders(cfg.OTLPHeaders))
	}

	return options
}

// metricHTTPOptions converts the local config into OTLP metric HTTP exporter options.
func metricHTTPOptions(cfg ObservabilityConfig) []otlpmetrichttp.Option {
	endpoint, insecure := normalizedOTLPEndpoint(cfg)

	options := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(endpoint)}
	if insecure {
		options = append(options, otlpmetrichttp.WithInsecure())
	}

	if len(cfg.OTLPHeaders) > 0 {
		options = append(options, otlpmetrichttp.WithHeaders(cfg.OTLPHeaders))
	}

	return options
}

// normalizedOTLPEndpoint accepts either host:port or a base URL and returns exporter host:port settings.
func normalizedOTLPEndpoint(cfg ObservabilityConfig) (string, bool) {
	endpoint := cfg.OTLPEndpoint
	if parsed, err := url.Parse(endpoint); err == nil && parsed.Host != "" {
		return parsed.Host, cfg.OTLPInsecure || parsed.Scheme == "http"
	}

	return endpoint, cfg.OTLPInsecure
}

// initializeOpenTelemetryInstruments creates the OTLP metric instruments.
func (o *Observability) initializeOpenTelemetryInstruments() error {
	instruments := &otelMetricInstruments{}

	if err := o.initializeOpenTelemetryRequestInstruments(instruments); err != nil {
		return err
	}

	if err := o.initializeOpenTelemetryDependencyInstruments(instruments); err != nil {
		return err
	}

	if err := o.initializeOpenTelemetryEventInstruments(instruments); err != nil {
		return err
	}

	o.otelMetrics = instruments

	return nil
}

// initializeOpenTelemetryRequestInstruments creates HTTP and policy metric instruments.
func (o *Observability) initializeOpenTelemetryRequestInstruments(instruments *otelMetricInstruments) error {
	var err error

	if instruments.httpRequests, err = o.meter.Int64Counter("geoip_policyd_http_requests"); err != nil {
		return err
	}

	if instruments.httpDuration, err = o.meter.Float64Histogram("geoip_policyd_http_request_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	if instruments.policyRequests, err = o.meter.Int64Counter("geoip_policyd_policy_requests"); err != nil {
		return err
	}

	if instruments.policyDuration, err = o.meter.Float64Histogram("geoip_policyd_policy_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	return nil
}

// initializeOpenTelemetryDependencyInstruments creates dependency metric instruments.
func (o *Observability) initializeOpenTelemetryDependencyInstruments(instruments *otelMetricInstruments) error {
	var err error

	if instruments.redisOperations, err = o.meter.Int64Counter("geoip_policyd_redis_operations"); err != nil {
		return err
	}

	if instruments.redisDuration, err = o.meter.Float64Histogram("geoip_policyd_redis_operation_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	if instruments.ldapOperations, err = o.meter.Int64Counter("geoip_policyd_ldap_operations"); err != nil {
		return err
	}

	if instruments.ldapDuration, err = o.meter.Float64Histogram("geoip_policyd_ldap_operation_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	if instruments.geoIPLookups, err = o.meter.Int64Counter("geoip_policyd_geoip_lookups"); err != nil {
		return err
	}

	if instruments.geoIPLookupDuration, err = o.meter.Float64Histogram("geoip_policyd_geoip_lookup_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	if instruments.cdbLookups, err = o.meter.Int64Counter("geoip_policyd_cdb_lookups"); err != nil {
		return err
	}

	if instruments.cdbDuration, err = o.meter.Float64Histogram("geoip_policyd_cdb_lookup_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	return nil
}

// initializeOpenTelemetryEventInstruments creates action, reload, and TCP metric instruments.
func (o *Observability) initializeOpenTelemetryEventInstruments(instruments *otelMetricInstruments) error {
	var err error

	if instruments.geoIPReloads, err = o.meter.Int64Counter("geoip_policyd_geoip_reloads"); err != nil {
		return err
	}

	if instruments.actions, err = o.meter.Int64Counter("geoip_policyd_actions"); err != nil {
		return err
	}

	if instruments.actionDuration, err = o.meter.Float64Histogram("geoip_policyd_action_duration", metric.WithUnit("s")); err != nil {
		return err
	}

	if instruments.tcpConnections, err = o.meter.Int64Counter("geoip_policyd_tcp_connections"); err != nil {
		return err
	}

	if instruments.tcpActive, err = o.meter.Int64UpDownCounter("geoip_policyd_tcp_active_connections"); err != nil {
		return err
	}

	return nil
}

// newPrometheusMetrics registers process, runtime, and application collectors.
func newPrometheusMetrics(registry *prometheus.Registry, runtimeMetrics bool) *prometheusMetrics {
	metrics := buildPrometheusMetrics()

	if runtimeMetrics {
		registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	registerPrometheusMetrics(registry, metrics)

	return metrics
}

// buildPrometheusMetrics creates all application collectors without registering them.
func buildPrometheusMetrics() *prometheusMetrics {
	return &prometheusMetrics{
		httpRequests:        newCounterVec("geoip_policyd_http_requests_total", "Total HTTP requests handled by the REST service.", labelMethod, labelPath, labelStatusClass),
		httpDuration:        newDurationVec("geoip_policyd_http_request_duration_seconds", "HTTP request duration in seconds.", labelMethod, labelPath, labelStatusClass),
		policyRequests:      newCounterVec("geoip_policyd_policy_requests_total", "Total policy requests by source and outcome.", labelSource, labelOutcome),
		policyDuration:      newDurationVec("geoip_policyd_policy_duration_seconds", "Policy request duration in seconds.", labelSource, labelOutcome),
		redisOperations:     newCounterVec("geoip_policyd_redis_operations_total", "Total Redis operations by role, operation, and result.", labelRole, labelOperation, labelResult),
		redisDuration:       newDurationVec("geoip_policyd_redis_operation_duration_seconds", "Redis operation duration in seconds.", labelRole, labelOperation, labelResult),
		ldapOperations:      newCounterVec("geoip_policyd_ldap_operations_total", "Total LDAP operations by operation and result.", labelOperation, labelResult),
		ldapDuration:        newDurationVec("geoip_policyd_ldap_operation_duration_seconds", "LDAP operation duration in seconds.", labelOperation, labelResult),
		ldapPoolConnections: newGaugeVec("geoip_policyd_ldap_pool_connections", "LDAP pool connection count by state.", labelState),
		geoIPLookups:        newCounterVec("geoip_policyd_geoip_lookups_total", "Total GeoIP lookups by result.", labelResult),
		geoIPLookupDuration: newDurationVec("geoip_policyd_geoip_lookup_duration_seconds", "GeoIP lookup duration in seconds.", labelResult),
		geoIPReloads:        newCounterVec("geoip_policyd_geoip_reloads_total", "Total GeoIP reload attempts by result.", labelResult),
		cdbLookups:          newCounterVec("geoip_policyd_cdb_lookups_total", "Total CDB lookup attempts by result.", labelResult),
		cdbDuration:         newDurationVec("geoip_policyd_cdb_lookup_duration_seconds", "CDB lookup duration in seconds.", labelResult),
		actions:             newCounterVec("geoip_policyd_actions_total", "Total actions by action name and result.", labelAction, labelResult),
		actionDuration:      newDurationVec("geoip_policyd_action_duration_seconds", "Action duration in seconds.", labelAction, labelResult),
		tcpConnections:      newCounterVec("geoip_policyd_tcp_connections_total", "Total TCP policy service connection events.", labelEvent, labelResult),
		tcpActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "geoip_policyd_tcp_active_connections",
			Help: "Currently active TCP policy service connections.",
		}),
	}
}

// newCounterVec builds a Prometheus counter vector with a consistent option shape.
func newCounterVec(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

// newDurationVec builds a Prometheus duration histogram vector with default buckets.
func newDurationVec(name, help string, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: prometheus.DefBuckets,
	}, labels)
}

// newGaugeVec builds a Prometheus gauge vector with a consistent option shape.
func newGaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

// registerPrometheusMetrics registers all application collectors.
func registerPrometheusMetrics(registry *prometheus.Registry, metrics *prometheusMetrics) {
	registry.MustRegister(
		metrics.httpRequests,
		metrics.httpDuration,
		metrics.policyRequests,
		metrics.policyDuration,
		metrics.redisOperations,
		metrics.redisDuration,
		metrics.ldapOperations,
		metrics.ldapDuration,
		metrics.ldapPoolConnections,
		metrics.geoIPLookups,
		metrics.geoIPLookupDuration,
		metrics.geoIPReloads,
		metrics.cdbLookups,
		metrics.cdbDuration,
		metrics.actions,
		metrics.actionDuration,
		metrics.tcpConnections,
		metrics.tcpActive,
	)
}

// PrometheusHandler returns the HTTP handler for this runtime's Prometheus registry.
func (o *Observability) PrometheusHandler() http.Handler {
	if o == nil || o.registry == nil {
		return http.NotFoundHandler()
	}

	return promhttp.HandlerFor(o.registry, promhttp.HandlerOpts{})
}

// PrometheusEnabled reports whether the Prometheus endpoint should be registered.
func (o *Observability) PrometheusEnabled() bool {
	return o != nil && o.config.PrometheusEnabled && o.registry != nil
}

// PrometheusPath returns the configured metrics path with its runtime default applied.
func (o *Observability) PrometheusPath() string {
	if o == nil || o.config.PrometheusPath == "" {
		return prometheusPath
	}

	return o.config.PrometheusPath
}

// InstrumentHTTP records HTTP duration metrics and wraps requests in a server span.
func (o *Observability) InstrumentHTTP(next http.Handler) http.Handler {
	if o == nil {
		return next
	}

	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		path := normalizeHTTPPath(request.URL.Path)
		start := time.Now()
		ctx := otel.GetTextMapPropagator().Extract(request.Context(), propagation.HeaderCarrier(request.Header))
		ctx, span := o.StartSpanWithKind(ctx,
			httpSpanName(request.Method, path),
			trace.SpanKindServer,
			attribute.String("http.request.method", request.Method),
			attribute.String("http.route", path),
			attribute.String("url.path", path),
		)
		request = request.WithContext(ctx)

		statusWriter := &statusResponseWriter{
			ResponseWriter: responseWriter,
			status:         http.StatusOK,
		}

		next.ServeHTTP(statusWriter, request)

		statusClass := httpStatusClass(statusWriter.status)
		o.ObserveHTTPRequest(ctx, request.Method, path, statusClass, time.Since(start))
		span.SetAttributes(attribute.Int("http.response.status_code", statusWriter.status))

		if statusWriter.status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(statusWriter.status))
		}

		span.End()
	})
}

// httpSpanName returns a low-cardinality server span name for one HTTP route.
func httpSpanName(method, route string) string {
	return fmt.Sprintf("HTTP %s %s", method, route)
}

// statusResponseWriter captures the status code emitted by an HTTP handler.
type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the status code before delegating to the wrapped writer.
func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Write preserves the implicit HTTP 200 status when handlers write a body first.
func (w *statusResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	return w.ResponseWriter.Write(data)
}

// StartSpan creates an internal trace span when tracing is enabled, otherwise it returns the existing no-op span.
func (o *Observability) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return o.StartSpanWithKind(ctx, name, trace.SpanKindInternal, attrs...)
}

// StartSpanWithKind creates a trace span with the supplied kind when tracing is enabled.
func (o *Observability) StartSpanWithKind(ctx context.Context, name string, kind trace.SpanKind, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}

	if o == nil || !o.config.OTelEnabled || !o.config.OTelTracesEnabled || o.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}

	return o.tracer.Start(ctx, name, trace.WithSpanKind(kind), trace.WithAttributes(attrs...))
}

// RecordSpanError annotates a span with an error and marks it failed.
func (o *Observability) RecordSpanError(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}

	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// Shutdown flushes OpenTelemetry providers before the process exits.
func (o *Observability) Shutdown(ctx context.Context) error {
	if o == nil {
		return nil
	}

	var shutdownErrors []error
	if o.meterProvider != nil {
		shutdownErrors = append(shutdownErrors, o.meterProvider.Shutdown(ctx))
	}

	if o.traceProvider != nil {
		shutdownErrors = append(shutdownErrors, o.traceProvider.Shutdown(ctx))
	}

	return errors.Join(shutdownErrors...)
}

// InstrumentRedisClient attaches a Redis hook that records command metrics and spans.
func (o *Observability) InstrumentRedisClient(client redis.UniversalClient, role string) {
	if o == nil || client == nil {
		return
	}

	client.AddHook(&redisObservabilityHook{obs: o, role: role})
}

// prometheusCounterDuration references one Prometheus counter and duration pair.
type prometheusCounterDuration struct {
	counter  *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// otelCounterDuration references one OpenTelemetry counter and duration pair.
type otelCounterDuration struct {
	counter  metric.Int64Counter
	duration metric.Float64Histogram
}

// observeCounterDuration records the same event in Prometheus and OpenTelemetry.
func (o *Observability) observeCounterDuration(ctx context.Context, prom prometheusCounterDuration, otelPair otelCounterDuration, labelValues []string, attrs []attribute.KeyValue, duration time.Duration) {
	if o == nil {
		return
	}

	if prom.counter != nil && prom.duration != nil {
		prom.counter.WithLabelValues(labelValues...).Inc()
		prom.duration.WithLabelValues(labelValues...).Observe(duration.Seconds())
	}

	if otelPair.counter != nil && otelPair.duration != nil {
		otelPair.counter.Add(ctx, 1, metric.WithAttributes(attrs...))
		otelPair.duration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
	}
}

// httpPrometheusPair returns the HTTP Prometheus counter and duration collectors.
func (o *Observability) httpPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.httpRequests, o.metrics.httpDuration}
}

// httpOTelPair returns the HTTP OpenTelemetry counter and duration instruments.
func (o *Observability) httpOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.httpRequests, o.otelMetrics.httpDuration}
}

// policyPrometheusPair returns the policy Prometheus counter and duration collectors.
func (o *Observability) policyPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.policyRequests, o.metrics.policyDuration}
}

// policyOTelPair returns the policy OpenTelemetry counter and duration instruments.
func (o *Observability) policyOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.policyRequests, o.otelMetrics.policyDuration}
}

// redisPrometheusPair returns the Redis Prometheus counter and duration collectors.
func (o *Observability) redisPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.redisOperations, o.metrics.redisDuration}
}

// redisOTelPair returns the Redis OpenTelemetry counter and duration instruments.
func (o *Observability) redisOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.redisOperations, o.otelMetrics.redisDuration}
}

// ldapPrometheusPair returns the LDAP Prometheus counter and duration collectors.
func (o *Observability) ldapPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.ldapOperations, o.metrics.ldapDuration}
}

// ldapOTelPair returns the LDAP OpenTelemetry counter and duration instruments.
func (o *Observability) ldapOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.ldapOperations, o.otelMetrics.ldapDuration}
}

// geoIPPrometheusPair returns the GeoIP Prometheus counter and duration collectors.
func (o *Observability) geoIPPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.geoIPLookups, o.metrics.geoIPLookupDuration}
}

// geoIPOTelPair returns the GeoIP OpenTelemetry counter and duration instruments.
func (o *Observability) geoIPOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.geoIPLookups, o.otelMetrics.geoIPLookupDuration}
}

// cdbPrometheusPair returns the CDB Prometheus counter and duration collectors.
func (o *Observability) cdbPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.cdbLookups, o.metrics.cdbDuration}
}

// cdbOTelPair returns the CDB OpenTelemetry counter and duration instruments.
func (o *Observability) cdbOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.cdbLookups, o.otelMetrics.cdbDuration}
}

// actionPrometheusPair returns the action Prometheus counter and duration collectors.
func (o *Observability) actionPrometheusPair() prometheusCounterDuration {
	if o == nil || o.metrics == nil {
		return prometheusCounterDuration{}
	}

	return prometheusCounterDuration{o.metrics.actions, o.metrics.actionDuration}
}

// actionOTelPair returns the action OpenTelemetry counter and duration instruments.
func (o *Observability) actionOTelPair() otelCounterDuration {
	if o == nil || o.otelMetrics == nil {
		return otelCounterDuration{}
	}

	return otelCounterDuration{o.otelMetrics.actions, o.otelMetrics.actionDuration}
}

// ObserveHTTPRequest records HTTP request metrics.
func (o *Observability) ObserveHTTPRequest(ctx context.Context, method, path, statusClass string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String(labelMethod, method),
		attribute.String(labelPath, path),
		attribute.String(labelStatusClass, statusClass),
	}
	o.observeCounterDuration(ctx, o.httpPrometheusPair(), o.httpOTelPair(), []string{method, path, statusClass}, attrs, duration)
}

// ObservePolicyRequest records one policy request outcome and duration.
func (o *Observability) ObservePolicyRequest(ctx context.Context, source, outcome string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String(labelSource, source),
		attribute.String(labelOutcome, outcome),
	}
	o.observeCounterDuration(ctx, o.policyPrometheusPair(), o.policyOTelPair(), []string{source, outcome}, attrs, duration)
}

// ObserveRedisOperation records one Redis operation outcome and duration.
func (o *Observability) ObserveRedisOperation(ctx context.Context, role, operation, result string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String(labelRole, role),
		attribute.String(labelOperation, operation),
		attribute.String(labelResult, result),
	}
	o.observeCounterDuration(ctx, o.redisPrometheusPair(), o.redisOTelPair(), []string{role, operation, result}, attrs, duration)
}

// ObserveLDAPOperation records one LDAP operation outcome and duration.
func (o *Observability) ObserveLDAPOperation(ctx context.Context, operation, result string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String(labelOperation, operation),
		attribute.String(labelResult, result),
	}
	o.observeCounterDuration(ctx, o.ldapPrometheusPair(), o.ldapOTelPair(), []string{operation, result}, attrs, duration)
}

// SetLDAPPoolConnections publishes LDAP pool state gauges.
func (o *Observability) SetLDAPPoolConnections(state string, count int) {
	if o == nil || o.metrics == nil {
		return
	}

	o.metrics.ldapPoolConnections.WithLabelValues(state).Set(float64(count))
}

// ObserveGeoIPLookup records one GeoIP lookup outcome and duration.
func (o *Observability) ObserveGeoIPLookup(ctx context.Context, result string, duration time.Duration) {
	attrs := []attribute.KeyValue{attribute.String(labelResult, result)}
	o.observeCounterDuration(ctx, o.geoIPPrometheusPair(), o.geoIPOTelPair(), []string{result}, attrs, duration)
}

// ObserveGeoIPReload records one GeoIP reload outcome.
func (o *Observability) ObserveGeoIPReload(ctx context.Context, result string) {
	if o == nil {
		return
	}

	if o.metrics != nil {
		o.metrics.geoIPReloads.WithLabelValues(result).Inc()
	}

	if o.otelMetrics != nil {
		o.otelMetrics.geoIPReloads.Add(ctx, 1, metric.WithAttributes(attribute.String(labelResult, result)))
	}
}

// ObserveCDBLookup records one CDB lookup outcome and duration.
func (o *Observability) ObserveCDBLookup(ctx context.Context, result string, duration time.Duration) {
	attrs := []attribute.KeyValue{attribute.String(labelResult, result)}
	o.observeCounterDuration(ctx, o.cdbPrometheusPair(), o.cdbOTelPair(), []string{result}, attrs, duration)
}

// ObserveAction records one action outcome and duration.
func (o *Observability) ObserveAction(ctx context.Context, action, result string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String(labelAction, action),
		attribute.String(labelResult, result),
	}
	o.observeCounterDuration(ctx, o.actionPrometheusPair(), o.actionOTelPair(), []string{action, result}, attrs, duration)
}

// ObserveTCPConnection records TCP policy service connection events and active connection deltas.
func (o *Observability) ObserveTCPConnection(ctx context.Context, event, result string, activeDelta int64) {
	if o == nil {
		return
	}

	if o.metrics != nil {
		o.metrics.tcpConnections.WithLabelValues(event, result).Inc()

		if activeDelta != 0 {
			o.metrics.tcpActive.Add(float64(activeDelta))
		}
	}

	if o.otelMetrics != nil {
		attrs := []attribute.KeyValue{
			attribute.String(labelEvent, event),
			attribute.String(labelResult, result),
		}

		o.otelMetrics.tcpConnections.Add(ctx, 1, metric.WithAttributes(attrs...))

		if activeDelta != 0 {
			o.otelMetrics.tcpActive.Add(ctx, activeDelta)
		}
	}
}

// redisObservabilityHook records Redis command, pipeline, and dial behavior.
type redisObservabilityHook struct {
	obs  *Observability
	role string
}

// DialHook wraps Redis connection establishment.
func (h *redisObservabilityHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		start := time.Now()
		conn, err := next(ctx, network, addr)
		result := resultFromError(err)
		h.obs.ObserveRedisOperation(ctx, h.role, operationRedisDial, result, time.Since(start))

		return conn, err
	}
}

// ProcessHook wraps a single Redis command.
func (h *redisObservabilityHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		operation := strings.ToLower(cmd.Name())
		start := time.Now()
		ctx, span := h.obs.StartSpanWithKind(ctx,
			redisCommandSpanName(operation),
			trace.SpanKindClient,
			attribute.String("db.system.name", "redis"),
			attribute.String("db.operation.name", operation),
			attribute.String("redis.role", h.role),
		)

		err := next(ctx, cmd)
		result := redisResultFromError(err)
		h.obs.ObserveRedisOperation(ctx, h.role, operation, result, time.Since(start))

		if err != nil && !errors.Is(err, redis.Nil) {
			h.obs.RecordSpanError(span, err)
		}

		span.SetAttributes(attribute.String(labelResult, result))
		span.End()

		return err
	}
}

// ProcessPipelineHook wraps Redis pipeline execution as one low-cardinality operation.
func (h *redisObservabilityHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		start := time.Now()
		ctx, span := h.obs.StartSpanWithKind(ctx,
			"redis.pipeline",
			trace.SpanKindClient,
			attribute.String("db.system.name", "redis"),
			attribute.Int("redis.command.count", len(cmds)),
			attribute.String("redis.role", h.role),
		)

		err := next(ctx, cmds)
		result := redisResultFromError(err)
		h.obs.ObserveRedisOperation(ctx, h.role, operationRedisPipeline, result, time.Since(start))

		if err != nil && !errors.Is(err, redis.Nil) {
			h.obs.RecordSpanError(span, err)
		}

		span.SetAttributes(attribute.String(labelResult, result))
		span.End()

		return err
	}
}

// redisCommandSpanName returns a low-cardinality Redis client span name.
func redisCommandSpanName(operation string) string {
	return fmt.Sprintf("redis.command %s", strings.ToUpper(operation))
}

// resultFromError normalizes errors into low-cardinality result labels.
func resultFromError(err error) string {
	if err != nil {
		return resultError
	}

	return resultOK
}

// redisResultFromError preserves Redis misses separately from transport or command errors.
func redisResultFromError(err error) string {
	if errors.Is(err, redis.Nil) {
		return resultMiss
	}

	return resultFromError(err)
}

// httpStatusClass maps a concrete status code to a low-cardinality class label.
func httpStatusClass(status int) string {
	if status <= 0 {
		status = http.StatusOK
	}

	return fmt.Sprintf("%dxx", status/100)
}

// normalizeHTTPPath limits metric cardinality to the known REST routes.
func normalizeHTTPPath(path string) string {
	switch path {
	case routeReload, routeCustomSettings, routeRemove, routeQuery, routeDovecotPolicy, routeModify, routeUpdate, prometheusPath:
		return path
	default:
		return routeOther
	}
}

// currentObservability returns the configured runtime without introducing another package-level service.
func currentObservability() *Observability {
	if config == nil {
		return nil
	}

	return config.observabilityRuntime
}
