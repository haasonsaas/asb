package main

import (
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evalops/asb/internal/bootstrap"
	"github.com/evalops/service-runtime/observability"
	"github.com/prometheus/client_golang/prometheus"
	goredis "github.com/redis/go-redis/v9"
)

func TestNewObservedHandlerServesMetrics(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics, err := observability.NewMetrics("asb", observability.MetricsOptions{
		Registerer: registry,
		Gatherer:   registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	handler := newObservedHandler(discardLogger(), metrics, mux)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/test", nil))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("content-type = %q, want Prometheus text output", got)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "asb_http_requests_total") {
		t.Fatalf("body = %q, want metrics payload", body)
	}
}

func TestNewObservedHandlerRecordsRequestMetrics(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics, err := observability.NewMetrics("asb", observability.MetricsOptions{
		Registerer: registry,
		Gatherer:   registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	handler := newObservedHandler(discardLogger(), metrics, mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if got := recorder.Header().Get("X-Request-Id"); got == "" {
		t.Fatal("expected X-Request-Id response header")
	}

	metricsRecorder := httptest.NewRecorder()
	handler.ServeHTTP(metricsRecorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metricsBody := metricsRecorder.Body.String()
	if !strings.Contains(metricsBody, `asb_http_requests_total{method="GET",route="/v1/test",status="201"} 1`) {
		t.Fatalf("metrics body = %q, want request counter sample", metricsBody)
	}
	if !strings.Contains(metricsBody, `asb_http_request_duration_seconds_count{method="GET",route="/v1/test",status="201"} 1`) {
		t.Fatalf("metrics body = %q, want request duration sample", metricsBody)
	}
}

func TestRegisterRuntimeMetricsRegistersDBStats(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	runtime := &bootstrap.ServiceRuntime{
		DBStats: func() sql.DBStats {
			return sql.DBStats{
				MaxOpenConnections: 8,
				OpenConnections:    5,
				InUse:              3,
				Idle:               2,
			}
		},
	}

	if err := registerRuntimeMetrics(runtime, registry); err != nil {
		t.Fatalf("registerRuntimeMetrics() error = %v", err)
	}

	metrics, err := observability.NewMetrics("asb", observability.MetricsOptions{
		Registerer: registry,
		Gatherer:   registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	handler := newObservedHandler(discardLogger(), metrics, http.NewServeMux())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := recorder.Body.String()
	if !strings.Contains(body, "asb_db_open_connections 5") {
		t.Fatalf("metrics body = %q, want open connection gauge", body)
	}
	if !strings.Contains(body, "asb_db_in_use_connections 3") {
		t.Fatalf("metrics body = %q, want in-use connection gauge", body)
	}
	if !strings.Contains(body, "asb_db_idle_connections 2") {
		t.Fatalf("metrics body = %q, want idle connection gauge", body)
	}
}

func TestRegisterRuntimeMetricsRegistersRedisStats(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	runtime := &bootstrap.ServiceRuntime{
		RedisStats: func() *goredis.PoolStats {
			return &goredis.PoolStats{
				Hits:            11,
				TotalConns:      5,
				IdleConns:       2,
				PendingRequests: 1,
			}
		},
	}

	if err := registerRuntimeMetrics(runtime, registry); err != nil {
		t.Fatalf("registerRuntimeMetrics() error = %v", err)
	}

	metrics, err := observability.NewMetrics("asb", observability.MetricsOptions{
		Registerer: registry,
		Gatherer:   registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	handler := newObservedHandler(discardLogger(), metrics, http.NewServeMux())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := recorder.Body.String()
	if !strings.Contains(body, "asb_redis_pool_total_connections 5") {
		t.Fatalf("metrics body = %q, want Redis total connection gauge", body)
	}
	if !strings.Contains(body, "asb_redis_pool_idle_connections 2") {
		t.Fatalf("metrics body = %q, want Redis idle connection gauge", body)
	}
	if !strings.Contains(body, "asb_redis_pool_hits_total 11") {
		t.Fatalf("metrics body = %q, want Redis hits counter", body)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
