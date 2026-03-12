package worker_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/haasonsaas/asb/internal/app"
	"github.com/haasonsaas/asb/internal/worker"
)

func TestRunner_RunOnce(t *testing.T) {
	t.Parallel()

	service := &fakeCleanupService{
		stats: &app.CleanupStats{
			ApprovalsExpired: 1,
			SessionsExpired:  2,
			GrantsExpired:    3,
			ArtifactsExpired: 4,
		},
	}
	runner := worker.NewRunner(worker.Config{
		Service: service,
		Limit:   50,
		Logger:  slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})

	stats, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if service.calls != 1 {
		t.Fatalf("service calls = %d, want 1", service.calls)
	}
	if stats.GrantsExpired != 3 {
		t.Fatalf("stats = %#v, want grants expired = 3", stats)
	}
}

func TestRunner_RunPropagatesErrors(t *testing.T) {
	t.Parallel()

	service := &fakeCleanupService{err: errors.New("boom")}
	runner := worker.NewRunner(worker.Config{
		Service:  service,
		Limit:    50,
		Interval: 5 * time.Millisecond,
		Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := runner.Run(ctx); err == nil {
		t.Fatal("Run() error = nil, want non-nil")
	}
}

type fakeCleanupService struct {
	stats *app.CleanupStats
	err   error
	calls int
}

func (f *fakeCleanupService) RunCleanupOnce(context.Context, int) (*app.CleanupStats, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.stats, nil
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
