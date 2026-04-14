package main

import (
	"log/slog"
	"net/http"

	"github.com/evalops/asb/internal/bootstrap"
	"github.com/evalops/service-runtime/httpkit"
	"github.com/evalops/service-runtime/observability"
	"github.com/prometheus/client_golang/prometheus"
)

func newObservedHandler(logger *slog.Logger, metrics *observability.Metrics, next http.Handler) http.Handler {
	observed := httpkit.WithRequestID(observability.RequestLoggingMiddleware(logger, metrics)(next))
	if metrics == nil {
		return observed
	}

	metricsHandler := metrics.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			metricsHandler.ServeHTTP(w, r)
			return
		}
		observed.ServeHTTP(w, r)
	})
}

func registerRuntimeMetrics(runtime *bootstrap.ServiceRuntime, registerer prometheus.Registerer) error {
	if runtime == nil || runtime.DBStats == nil {
		return nil
	}
	return observability.RegisterDBStats("asb", runtime.DBStats, observability.DBStatsOptions{
		Registerer: registerer,
	})
}
