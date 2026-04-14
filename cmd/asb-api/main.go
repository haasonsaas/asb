package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/evalops/asb/internal/api/connectapi"
	"github.com/evalops/asb/internal/api/httpapi"
	"github.com/evalops/asb/internal/bootstrap"
	"github.com/evalops/service-runtime/ratelimit"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runtime, err := bootstrap.NewServiceRuntime(ctx, logger)
	if err != nil {
		logger.Error("bootstrap service", "error", err)
		os.Exit(1)
	}
	defer runtime.Cleanup()

	cfg, err := loadServerConfig()
	if err != nil {
		logger.Error("load server config", "error", err)
		os.Exit(1)
	}

	limiter := ratelimit.New(ratelimit.Config{
		RequestsPerSecond: cfg.rateLimitRPS,
		Burst:             cfg.rateLimitBurst,
		CleanupInterval:   cfg.rateLimitCleanup,
		MaxAge:            cfg.rateLimitMaxAge,
		ExemptPaths:       ratelimit.DefaultConfig().ExemptPaths,
	})
	defer limiter.Close()

	mux := http.NewServeMux()
	mux.Handle("/v1/", httpapi.NewServer(
		runtime.Service,
		httpapi.WithMaxBodyBytes(cfg.maxBodyBytes),
		httpapi.WithRequestTimeouts(cfg.defaultTimeout, cfg.grantTimeout, cfg.proxyTimeout),
		httpapi.WithRateLimiter(limiter),
	))
	connectPath, connectHandler := connectapi.NewHandler(runtime.Service)
	mux.Handle(connectPath, connectHandler)
	registerHealthHandlers(mux, runtime.Health, cfg.readyTimeout)

	server := &http.Server{
		Addr:         cfg.addr,
		Handler:      mux,
		ReadTimeout:  cfg.readTimeout,
		WriteTimeout: cfg.writeTimeout,
		IdleTimeout:  cfg.idleTimeout,
	}

	logger.Info("starting asb api",
		"addr", cfg.addr,
		"max_body_bytes", cfg.maxBodyBytes,
		"read_timeout", cfg.readTimeout,
		"write_timeout", cfg.writeTimeout,
		"idle_timeout", cfg.idleTimeout,
		"ready_timeout", cfg.readyTimeout,
		"shutdown_timeout", cfg.shutdownTimeout,
		"default_timeout", cfg.defaultTimeout,
		"grant_timeout", cfg.grantTimeout,
		"proxy_timeout", cfg.proxyTimeout,
		"rate_limit_rps", cfg.rateLimitRPS,
		"rate_limit_burst", cfg.rateLimitBurst,
		"rate_limit_max_age", cfg.rateLimitMaxAge,
		"rate_limit_cleanup_interval", cfg.rateLimitCleanup,
	)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited", "error", err)
			os.Exit(1)
		}
		return
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown server", "error", err)
		os.Exit(1)
	}

	if err := <-serverErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server exited after shutdown", "error", err)
		os.Exit(1)
	}
}

func getenv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
