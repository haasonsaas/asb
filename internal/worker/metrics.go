package worker

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/evalops/asb/internal/app"
	"github.com/prometheus/client_golang/prometheus"
)

type MetricsOptions struct {
	Registerer      prometheus.Registerer
	DurationBuckets []float64
}

type Metrics struct {
	processed *prometheus.CounterVec
	duration  prometheus.Histogram
}

func NewMetrics(serviceName string, opts MetricsOptions) (*Metrics, error) {
	if opts.Registerer == nil {
		opts.Registerer = prometheus.DefaultRegisterer
	}
	if len(opts.DurationBuckets) == 0 {
		opts.DurationBuckets = prometheus.DefBuckets
	}

	prefix := metricsPrefix(serviceName)
	processed, err := registerCounterVec(
		opts.Registerer,
		prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: prefix + "_cleanup_processed_total",
				Help: "Count of ASB cleanup items processed by type.",
			},
			[]string{"item_type"},
		),
	)
	if err != nil {
		return nil, err
	}

	duration, err := registerHistogram(
		opts.Registerer,
		prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    prefix + "_cleanup_pass_seconds",
				Help:    "Duration of ASB cleanup passes in seconds.",
				Buckets: opts.DurationBuckets,
			},
		),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		processed: processed,
		duration:  duration,
	}, nil
}

func (m *Metrics) recordCleanupPass(stats *app.CleanupStats, duration time.Duration) {
	if m == nil {
		return
	}
	m.duration.Observe(duration.Seconds())
	if stats == nil {
		return
	}
	m.processed.WithLabelValues("approvals").Add(float64(stats.ApprovalsExpired))
	m.processed.WithLabelValues("sessions").Add(float64(stats.SessionsExpired))
	m.processed.WithLabelValues("grants").Add(float64(stats.GrantsExpired))
	m.processed.WithLabelValues("artifacts").Add(float64(stats.ArtifactsExpired))
}

func metricsPrefix(serviceName string) string {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return "service"
	}

	var builder strings.Builder
	for index, runeValue := range serviceName {
		switch {
		case unicode.IsLetter(runeValue), unicode.IsDigit(runeValue):
			builder.WriteRune(unicode.ToLower(runeValue))
		default:
			builder.WriteByte('_')
		}
		if index == 0 && unicode.IsDigit(runeValue) {
			builder.WriteByte('_')
		}
	}

	prefix := strings.Trim(builder.String(), "_")
	if prefix == "" {
		return "service"
	}
	if prefix[0] >= '0' && prefix[0] <= '9' {
		return "service_" + prefix
	}
	return prefix
}

func registerCounterVec(registerer prometheus.Registerer, collector *prometheus.CounterVec) (*prometheus.CounterVec, error) {
	if err := registerer.Register(collector); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
		if !ok {
			return nil, err
		}
		return existing, nil
	}
	return collector, nil
}

func registerHistogram(registerer prometheus.Registerer, collector prometheus.Histogram) (prometheus.Histogram, error) {
	if err := registerer.Register(collector); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Histogram)
		if !ok {
			return nil, fmt.Errorf("register histogram: existing collector has unexpected type %T", alreadyRegistered.ExistingCollector)
		}
		return existing, nil
	}
	return collector, nil
}
