package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/evalops/asb/internal/api/connectapi"
	"github.com/evalops/asb/internal/api/httpapi"
	"github.com/evalops/asb/internal/bootstrap"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	svc, cleanup, err := bootstrap.NewService(ctx, logger)
	if err != nil {
		logger.Error("bootstrap service", "error", err)
		os.Exit(1)
	}
	defer cleanup()

	cfg, err := loadServerConfig()
	if err != nil {
		logger.Error("load server config", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/", httpapi.NewServer(
		svc,
		httpapi.WithMaxBodyBytes(cfg.maxBodyBytes),
		httpapi.WithRequestTimeouts(cfg.defaultTimeout, cfg.grantTimeout, cfg.proxyTimeout),
	))
	connectPath, connectHandler := connectapi.NewHandler(svc)
	mux.Handle(connectPath, connectHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

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
		"default_timeout", cfg.defaultTimeout,
		"grant_timeout", cfg.grantTimeout,
		"proxy_timeout", cfg.proxyTimeout,
	)
	if err := server.ListenAndServe(); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func getenv(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
