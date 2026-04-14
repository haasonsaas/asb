package worker_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/evalops/asb/internal/app"
	"github.com/evalops/asb/internal/worker"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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

func TestRunner_RunOnceRecordsMetrics(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	metrics, err := worker.NewMetrics("asb", worker.MetricsOptions{
		Registerer: registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

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
		Metrics: metrics,
	})

	if _, err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}

	families := mustGatherMetrics(t, registry)
	if got := metricValueWithLabels(families, "asb_cleanup_processed_total", map[string]string{"item_type": "approvals"}); got != 1 {
		t.Fatalf("approval cleanup count = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_cleanup_processed_total", map[string]string{"item_type": "sessions"}); got != 2 {
		t.Fatalf("session cleanup count = %v, want 2", got)
	}
	if got := metricValueWithLabels(families, "asb_cleanup_processed_total", map[string]string{"item_type": "grants"}); got != 3 {
		t.Fatalf("grant cleanup count = %v, want 3", got)
	}
	if got := metricValueWithLabels(families, "asb_cleanup_processed_total", map[string]string{"item_type": "artifacts"}); got != 4 {
		t.Fatalf("artifact cleanup count = %v, want 4", got)
	}
	if got := histogramCountWithLabels(families, "asb_cleanup_pass_seconds", nil); got != 1 {
		t.Fatalf("cleanup pass histogram count = %d, want 1", got)
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

func TestRunner_RunDrainsCurrentPassBeforeExit(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	service := &fakeCleanupService{
		stats: &app.CleanupStats{},
		runCleanupOnce: func(ctx context.Context, limit int) (*app.CleanupStats, error) {
			close(started)
			<-release
			return &app.CleanupStats{}, nil
		},
	}
	runner := worker.NewRunner(worker.Config{
		Service:  service,
		Limit:    50,
		Interval: 5 * time.Millisecond,
		Logger:   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runner.Run(ctx)
	}()

	<-started
	cancel()
	close(release)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not exit after draining current pass")
	}

	service.mu.Lock()
	calls := service.calls
	service.mu.Unlock()
	if calls != 1 {
		t.Fatalf("service calls = %d, want 1", calls)
	}
}

type fakeCleanupService struct {
	stats          *app.CleanupStats
	err            error
	runCleanupOnce func(context.Context, int) (*app.CleanupStats, error)
	calls          int
	mu             sync.Mutex
}

func (f *fakeCleanupService) RunCleanupOnce(ctx context.Context, limit int) (*app.CleanupStats, error) {
	f.mu.Lock()
	f.calls++
	runCleanupOnce := f.runCleanupOnce
	stats := f.stats
	err := f.err
	f.mu.Unlock()

	if runCleanupOnce != nil {
		return runCleanupOnce(ctx, limit)
	}
	if err != nil {
		return nil, err
	}
	return stats, nil
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func mustGatherMetrics(t *testing.T, gatherer prometheus.Gatherer) []*dto.MetricFamily {
	t.Helper()

	families, err := gatherer.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	return families
}

func metricValueWithLabels(metricFamilies []*dto.MetricFamily, name string, labels map[string]string) float64 {
	for _, family := range metricFamilies {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if !metricMatchesLabels(metric, labels) {
				continue
			}
			switch family.GetType() {
			case dto.MetricType_COUNTER:
				return metric.GetCounter().GetValue()
			case dto.MetricType_GAUGE:
				return metric.GetGauge().GetValue()
			}
		}
	}
	return 0
}

func histogramCountWithLabels(metricFamilies []*dto.MetricFamily, name string, labels map[string]string) uint64 {
	for _, family := range metricFamilies {
		if family.GetName() != name || family.GetType() != dto.MetricType_HISTOGRAM {
			continue
		}
		for _, metric := range family.Metric {
			if metricMatchesLabels(metric, labels) {
				return metric.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

func metricMatchesLabels(metric *dto.Metric, labels map[string]string) bool {
	if len(labels) == 0 {
		return true
	}
	values := make(map[string]string, len(metric.Label))
	for _, label := range metric.Label {
		values[label.GetName()] = label.GetValue()
	}
	for key, want := range labels {
		if values[key] != want {
			return false
		}
	}
	return true
}
