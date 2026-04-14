package app

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/evalops/asb/internal/core"
	"github.com/prometheus/client_golang/prometheus"
)

// MetricsOptions configures Prometheus registration for ASB domain metrics.
type MetricsOptions struct {
	Registerer          prometheus.Registerer
	GrantTTLBuckets     []float64
	ApprovalWaitBuckets []float64
}

// Metrics records ASB domain-level counters, gauges, and histograms.
type Metrics struct {
	sessionsActive *prometheus.GaugeVec
	sessionsTotal  *prometheus.CounterVec
	grantsTotal    *prometheus.CounterVec
	grantTTL       prometheus.Histogram
	approvalsTotal *prometheus.CounterVec
	approvalWait   *prometheus.HistogramVec
	policyEval     *prometheus.CounterVec
	budgetExhaust  *prometheus.CounterVec
}

// NewMetrics creates Prometheus collectors for ASB domain metrics.
func NewMetrics(serviceName string, opts MetricsOptions) (*Metrics, error) {
	opts = opts.withDefaults()
	prefix := metricsPrefix(serviceName)

	sessionsActive, err := registerGaugeVec(
		opts.Registerer,
		prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prefix + "_sessions_active",
				Help: "Current number of active ASB sessions by tenant.",
			},
			[]string{"tenant"},
		),
	)
	if err != nil {
		return nil, err
	}

	sessionsTotal, err := registerCounterVec(
		opts.Registerer,
		prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: prefix + "_sessions_total",
				Help: "Count of ASB sessions by lifecycle outcome.",
			},
			[]string{"outcome"},
		),
	)
	if err != nil {
		return nil, err
	}

	grantsTotal, err := registerCounterVec(
		opts.Registerer,
		prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: prefix + "_grants_total",
				Help: "Count of ASB grants by lifecycle outcome.",
			},
			[]string{"outcome"},
		),
	)
	if err != nil {
		return nil, err
	}

	grantTTL, err := registerHistogram(
		opts.Registerer,
		prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    prefix + "_grant_ttl_seconds",
				Help:    "Effective TTL of ASB grants in seconds.",
				Buckets: opts.GrantTTLBuckets,
			},
		),
	)
	if err != nil {
		return nil, err
	}

	approvalsTotal, err := registerCounterVec(
		opts.Registerer,
		prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: prefix + "_approvals_total",
				Help: "Count of ASB approvals by outcome.",
			},
			[]string{"outcome"},
		),
	)
	if err != nil {
		return nil, err
	}

	approvalWait, err := registerHistogramVec(
		opts.Registerer,
		prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    prefix + "_approval_wait_seconds",
				Help:    "Time spent waiting on ASB approvals in seconds.",
				Buckets: opts.ApprovalWaitBuckets,
			},
			[]string{"outcome"},
		),
	)
	if err != nil {
		return nil, err
	}

	policyEval, err := registerCounterVec(
		opts.Registerer,
		prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: prefix + "_policy_evaluations_total",
				Help: "Count of ASB policy evaluations by capability and outcome.",
			},
			[]string{"capability", "outcome"},
		),
	)
	if err != nil {
		return nil, err
	}

	budgetExhaust, err := registerCounterVec(
		opts.Registerer,
		prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: prefix + "_budget_exhaustion_total",
				Help: "Count of ASB proxy budget exhaustion events by handle.",
			},
			[]string{"handle"},
		),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		sessionsActive: sessionsActive,
		sessionsTotal:  sessionsTotal,
		grantsTotal:    grantsTotal,
		grantTTL:       grantTTL,
		approvalsTotal: approvalsTotal,
		approvalWait:   approvalWait,
		policyEval:     policyEval,
		budgetExhaust:  budgetExhaust,
	}, nil
}

func (opts MetricsOptions) withDefaults() MetricsOptions {
	if opts.Registerer == nil {
		opts.Registerer = prometheus.DefaultRegisterer
	}
	if len(opts.GrantTTLBuckets) == 0 {
		opts.GrantTTLBuckets = []float64{30, 60, 120, 300, 600, 900, 1800, 3600}
	}
	if len(opts.ApprovalWaitBuckets) == 0 {
		opts.ApprovalWaitBuckets = []float64{1, 5, 15, 30, 60, 120, 300, 600}
	}
	return opts
}

func (metrics *Metrics) recordSessionCreated(tenantID string) {
	if metrics == nil {
		return
	}
	metrics.sessionsTotal.WithLabelValues("created").Inc()
	metrics.sessionsActive.WithLabelValues(labelOrUnknown(tenantID)).Inc()
}

func (metrics *Metrics) recordSessionTransition(previous, next core.SessionState, tenantID string) {
	if metrics == nil || previous == next {
		return
	}
	switch next {
	case core.SessionStateRevoked, core.SessionStateExpired:
		if previous == core.SessionStateActive {
			metrics.sessionsActive.WithLabelValues(labelOrUnknown(tenantID)).Dec()
		}
		metrics.sessionsTotal.WithLabelValues(string(next)).Inc()
	}
}

func (metrics *Metrics) recordGrantCreated(state core.GrantState, ttl time.Duration) {
	if metrics == nil {
		return
	}
	if state != "" {
		metrics.grantsTotal.WithLabelValues(string(state)).Inc()
	}
	if ttl > 0 {
		metrics.grantTTL.Observe(ttl.Seconds())
	}
}

func (metrics *Metrics) recordGrantTransition(state core.GrantState) {
	if metrics == nil || state == "" {
		return
	}
	metrics.grantsTotal.WithLabelValues(string(state)).Inc()
}

func (metrics *Metrics) recordApprovalTransition(state core.ApprovalState, wait time.Duration) {
	if metrics == nil || state == "" {
		return
	}
	switch state {
	case core.ApprovalStateApproved, core.ApprovalStateDenied, core.ApprovalStateExpired:
		metrics.approvalsTotal.WithLabelValues(string(state)).Inc()
		metrics.approvalWait.WithLabelValues(string(state)).Observe(wait.Seconds())
	}
}

func (metrics *Metrics) recordPolicyEvaluation(capability string, allowed bool) {
	if metrics == nil {
		return
	}
	outcome := "denied"
	if allowed {
		outcome = "allowed"
	}
	metrics.policyEval.WithLabelValues(labelOrUnknown(capability), outcome).Inc()
}

func (metrics *Metrics) recordBudgetExhaustion(handle string) {
	if metrics == nil {
		return
	}
	metrics.budgetExhaust.WithLabelValues(labelOrUnknown(handle)).Inc()
}

func labelOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
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

func registerGaugeVec(registerer prometheus.Registerer, collector *prometheus.GaugeVec) (*prometheus.GaugeVec, error) {
	if err := registerer.Register(collector); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.GaugeVec)
		if !ok {
			return nil, err
		}
		return existing, nil
	}
	return collector, nil
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

func registerHistogramVec(registerer prometheus.Registerer, collector *prometheus.HistogramVec) (*prometheus.HistogramVec, error) {
	if err := registerer.Register(collector); err != nil {
		alreadyRegistered, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			return nil, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.HistogramVec)
		if !ok {
			return nil, err
		}
		return existing, nil
	}
	return collector, nil
}
