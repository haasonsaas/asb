package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/haasonsaas/asb/internal/api/connectapi"
	"github.com/haasonsaas/asb/internal/api/httpapi"
	"github.com/haasonsaas/asb/internal/bootstrap"
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

	addr := getenv("ASB_ADDR", ":8080")
	mux := http.NewServeMux()
	mux.Handle("/v1/", httpapi.NewServer(svc))
	connectPath, connectHandler := connectapi.NewHandler(svc)
	mux.Handle(connectPath, connectHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	logger.Info("starting asb api", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
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
