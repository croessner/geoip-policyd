package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

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
