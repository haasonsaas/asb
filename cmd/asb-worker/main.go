package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/haasonsaas/asb/internal/bootstrap"
	"github.com/haasonsaas/asb/internal/worker"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var (
		interval time.Duration
		limit    int
		once     bool
	)
	flag.DurationVar(&interval, "interval", 30*time.Second, "cleanup interval")
	flag.IntVar(&limit, "limit", 100, "maximum expired items processed per cleanup pass")
	flag.BoolVar(&once, "once", false, "run a single cleanup pass and exit")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	svc, cleanup, err := bootstrap.NewService(ctx, logger, bootstrap.WithVerificationOptional())
	if err != nil {
		logger.Error("bootstrap service", "error", err)
		os.Exit(1)
	}
	defer cleanup()

	runner := worker.NewRunner(worker.Config{
		Service:  svc,
		Interval: interval,
		Limit:    limit,
		Logger:   logger,
	})

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
