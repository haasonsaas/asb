package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/evalops/asb/internal/bootstrap"
	"github.com/evalops/asb/internal/worker"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var (
		interval    time.Duration
		limit       int
		once        bool
		metricsAddr string
	)
	flag.DurationVar(&interval, "interval", 30*time.Second, "cleanup interval")
	flag.IntVar(&limit, "limit", 100, "maximum expired items processed per cleanup pass")
	flag.BoolVar(&once, "once", false, "run a single cleanup pass and exit")
	flag.StringVar(&metricsAddr, "metrics-addr", os.Getenv("ASB_WORKER_METRICS_ADDR"), "optional metrics listen address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	svc, cleanup, err := bootstrap.NewService(ctx, logger, bootstrap.WithVerificationOptional())
	if err != nil {
		logger.Error("bootstrap service", "error", err)
		os.Exit(1)
	}
	defer cleanup()

	workerMetrics, err := worker.NewMetrics("asb", worker.MetricsOptions{
		Registerer: prometheus.DefaultRegisterer,
	})
	if err != nil {
		logger.Error("configure worker metrics", "error", err)
		os.Exit(1)
	}

	runner := worker.NewRunner(worker.Config{
		Service:  svc,
		Interval: interval,
		Limit:    limit,
		Logger:   logger,
		Metrics:  workerMetrics,
	})

	var metricsServer *http.Server
	if metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		metricsServer = &http.Server{
			Addr:    metricsAddr,
			Handler: mux,
		}
		go func() {
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("worker metrics server exited", "error", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = metricsServer.Shutdown(shutdownCtx)
		}()
		logger.Info("worker metrics server listening", "addr", metricsAddr)
	}

	if once {
		if _, err := runner.RunOnce(ctx); err != nil {
			logger.Error("worker cleanup pass failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if err := runner.Run(ctx); err != nil {
		logger.Error("worker exited", "error", err)
		os.Exit(1)
	}
}
