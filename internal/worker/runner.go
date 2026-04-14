package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/evalops/asb/internal/app"
)

type CleanupService interface {
	RunCleanupOnce(ctx context.Context, limit int) (*app.CleanupStats, error)
}

type Config struct {
	Service  CleanupService
	Interval time.Duration
	Limit    int
	Logger   *slog.Logger
	Metrics  *Metrics
}

type Runner struct {
	service  CleanupService
	interval time.Duration
	limit    int
	logger   *slog.Logger
	metrics  *Metrics
}

func NewRunner(cfg Config) *Runner {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 100
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Runner{
		service:  cfg.Service,
		interval: cfg.Interval,
		limit:    cfg.Limit,
		logger:   cfg.Logger,
		metrics:  cfg.Metrics,
	}
}

func (r *Runner) RunOnce(ctx context.Context) (*app.CleanupStats, error) {
	if r.service == nil {
		return nil, fmt.Errorf("cleanup service is required")
	}
	startedAt := time.Now()
	stats, err := r.service.RunCleanupOnce(ctx, r.limit)
	if err != nil {
		return nil, err
	}
	r.metrics.recordCleanupPass(stats, time.Since(startedAt))
	r.logger.Info("worker cleanup complete",
		"approvals_expired", stats.ApprovalsExpired,
		"sessions_expired", stats.SessionsExpired,
		"grants_expired", stats.GrantsExpired,
		"artifacts_expired", stats.ArtifactsExpired,
	)
	return stats, nil
}

func (r *Runner) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	if _, err := r.RunOnce(context.WithoutCancel(ctx)); err != nil {
		return err
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := r.RunOnce(context.WithoutCancel(ctx)); err != nil {
				return err
			}
		}
	}
}
