package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/evalops/asb/internal/app"
	"github.com/evalops/asb/internal/audit/memory"
	"github.com/evalops/asb/internal/authz/policy"
	"github.com/evalops/asb/internal/authz/toolregistry"
	"github.com/evalops/asb/internal/core"
	memstore "github.com/evalops/asb/internal/store/memory"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestServiceMetrics_CreateSessionAndIssueGrant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	registry := prometheus.NewRegistry()
	metrics, err := app.NewMetrics("asb", app.MetricsOptions{
		Registerer:      registry,
		GrantTTLBuckets: []float64{60, 600, 1800},
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	repo := memstore.NewRepository()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "github",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindProxyHandle,
			Metadata: map[string]string{
				"handle": "ph_metrics_1",
			},
		},
	}
	delivery := &fakeDeliveryAdapter{
		mode: core.DeliveryModeProxy,
		delivery: &core.Delivery{
			Kind:   core.DeliveryKindProxyHandle,
			Handle: "ph_metrics_1",
		},
	}

	mustPutTool(t, ctx, tools, core.Tool{
		TenantID:             "t_acme",
		Tool:                 "github",
		ManifestHash:         "sha256:test",
		RuntimeClass:         core.RuntimeClassHosted,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		AllowedCapabilities:  []string{"repo.read"},
		TrustTags:            []string{"trusted", "github"},
	})
	mustPutPolicy(t, engine, core.Policy{
		TenantID:             "t_acme",
		Capability:           "repo.read",
		ResourceKind:         core.ResourceKindGitHubRepo,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		DefaultTTL:           10 * time.Minute,
		MaxTTL:               10 * time.Minute,
		ApprovalMode:         core.ApprovalModeNone,
		RequiredToolTags:     []string{"trusted", "github"},
		Condition:            `true`,
	})

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("sess_metrics_1", "evt_1", "gr_metrics_1", "evt_2", "evt_3"),
		Metrics:       metrics,
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        engine,
		Tools:         tools,
		Connectors:    fakeConnectorResolver{connector: connector},
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeProxy: delivery,
		},
		ApprovalNotifier: noopApprovalNotifier{},
		Audit:            memory.NewSink(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "agent_pr_reviewer",
		RunID:       "run_metrics_1",
		ToolContext: []string{"github"},
		Attestation: &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if _, err := svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "github",
		Capability:   "repo.read",
		ResourceRef:  "github:repo:acme/widgets",
		DeliveryMode: core.DeliveryModeProxy,
		TTL:          20 * time.Minute,
		Reason:       "metrics coverage",
	}); err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}

	families := mustGatherMetrics(t, registry)
	if got := metricValueWithLabels(families, "asb_sessions_active", map[string]string{"tenant": "t_acme"}); got != 1 {
		t.Fatalf("active sessions = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_sessions_total", map[string]string{"outcome": "created"}); got != 1 {
		t.Fatalf("created sessions = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_grants_total", map[string]string{"outcome": "issued"}); got != 1 {
		t.Fatalf("issued grants = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_artifacts_active", map[string]string{"connector_kind": "github"}); got != 1 {
		t.Fatalf("active github artifacts = %v, want 1", got)
	}
	if got := histogramCountWithLabels(families, "asb_grant_ttl_seconds", nil); got != 1 {
		t.Fatalf("grant TTL histogram count = %d, want 1", got)
	}
}

func TestServiceMetrics_ApprovalFlow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	registry := prometheus.NewRegistry()
	metrics, err := app.NewMetrics("asb", app.MetricsOptions{
		Registerer:          registry,
		GrantTTLBuckets:     []float64{60, 300, 600},
		ApprovalWaitBuckets: []float64{1, 60, 300},
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	repo := memstore.NewRepository()
	auditSink := memory.NewSink()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "browser",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindWrappedSecret,
			Metadata: map[string]string{
				"artifact_id": "art_browser_metrics",
			},
			SecretData: map[string]string{
				"username": "admin",
				"password": "redacted",
			},
		},
	}
	delivery := &fakeDeliveryAdapter{
		mode: core.DeliveryModeWrappedSecret,
		delivery: &core.Delivery{
			Kind:       core.DeliveryKindWrappedSecret,
			ArtifactID: "art_browser_metrics",
		},
	}

	mustPutTool(t, ctx, tools, core.Tool{
		TenantID:             "t_acme",
		Tool:                 "browser",
		ManifestHash:         "sha256:browser",
		RuntimeClass:         core.RuntimeClassBrowser,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
		AllowedCapabilities:  []string{"browser.login"},
		TrustTags:            []string{"trusted", "browser"},
	})
	mustPutPolicy(t, engine, core.Policy{
		TenantID:             "t_acme",
		Capability:           "browser.login",
		ResourceKind:         core.ResourceKindBrowserOrigin,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
		DefaultTTL:           2 * time.Minute,
		MaxTTL:               5 * time.Minute,
		ApprovalMode:         core.ApprovalModeLiveHuman,
		RequiredToolTags:     []string{"trusted", "browser"},
		Condition:            `request.origin == "https://admin.vendor.example" && session.tool_context.exists(t, t == "browser")`,
	})

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("sess_browser_metrics", "evt_1", "gr_browser_metrics", "ap_browser_metrics", "evt_2", "evt_3", "art_browser_metrics", "evt_4", "evt_5"),
		Metrics:       metrics,
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        engine,
		Tools:         tools,
		Connectors:    fakeConnectorResolver{connector: connector},
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeWrappedSecret: delivery,
		},
		ApprovalNotifier: noopApprovalNotifier{},
		Audit:            auditSink,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "browser_agent",
		RunID:       "run_metrics_2",
		ToolContext: []string{"browser"},
		Attestation: &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	grantResp, err := svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "browser",
		Capability:   "browser.login",
		ResourceRef:  "browser_origin:https://admin.vendor.example",
		DeliveryMode: core.DeliveryModeWrappedSecret,
		TTL:          5 * time.Minute,
		Reason:       "metrics browser login",
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if _, err := svc.ApproveGrant(ctx, &core.ApproveGrantRequest{
		ApprovalID: grantResp.ApprovalID,
		Approver:   "user:jonathan",
		Comment:    "approved for metrics",
	}); err != nil {
		t.Fatalf("ApproveGrant() error = %v", err)
	}

	families := mustGatherMetrics(t, registry)
	if got := metricValueWithLabels(families, "asb_grants_total", map[string]string{"outcome": "pending"}); got != 1 {
		t.Fatalf("pending grants = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_grants_total", map[string]string{"outcome": "issued"}); got != 1 {
		t.Fatalf("issued grants = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_approvals_total", map[string]string{"outcome": "approved"}); got != 1 {
		t.Fatalf("approved approvals = %v, want 1", got)
	}
	if got := histogramCountWithLabels(families, "asb_approval_wait_seconds", map[string]string{"outcome": "approved"}); got != 1 {
		t.Fatalf("approval wait histogram count = %d, want 1", got)
	}
}

func TestServiceMetrics_RevokeSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	registry := prometheus.NewRegistry()
	metrics, err := app.NewMetrics("asb", app.MetricsOptions{
		Registerer: registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	repo := memstore.NewRepository()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "github",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindProxyHandle,
			Metadata: map[string]string{
				"handle": "ph_metrics_revoke",
			},
		},
	}
	delivery := &fakeDeliveryAdapter{
		mode: core.DeliveryModeProxy,
		delivery: &core.Delivery{
			Kind:   core.DeliveryKindProxyHandle,
			Handle: "ph_metrics_revoke",
		},
	}

	mustPutTool(t, ctx, tools, core.Tool{
		TenantID:             "t_acme",
		Tool:                 "github",
		ManifestHash:         "sha256:test",
		RuntimeClass:         core.RuntimeClassHosted,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		AllowedCapabilities:  []string{"repo.read"},
		TrustTags:            []string{"trusted", "github"},
	})
	mustPutPolicy(t, engine, core.Policy{
		TenantID:             "t_acme",
		Capability:           "repo.read",
		ResourceKind:         core.ResourceKindGitHubRepo,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		DefaultTTL:           10 * time.Minute,
		MaxTTL:               10 * time.Minute,
		ApprovalMode:         core.ApprovalModeNone,
		RequiredToolTags:     []string{"trusted", "github"},
		Condition:            `true`,
	})

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("sess_rev_metrics", "evt_1", "gr_rev_metrics", "art_rev_metrics", "evt_2", "evt_3", "evt_4"),
		Metrics:       metrics,
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        engine,
		Tools:         tools,
		Connectors:    fakeConnectorResolver{connector: connector},
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeProxy: delivery,
		},
		ApprovalNotifier: noopApprovalNotifier{},
		Audit:            memory.NewSink(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "agent_pr_reviewer",
		RunID:       "run_metrics_3",
		ToolContext: []string{"github"},
		Attestation: &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	grantResp, err := svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "github",
		Capability:   "repo.read",
		ResourceRef:  "github:repo:acme/widgets",
		DeliveryMode: core.DeliveryModeProxy,
		TTL:          10 * time.Minute,
		Reason:       "revoke metrics",
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if err := svc.RevokeSession(ctx, &core.RevokeSessionRequest{
		SessionID: sessionResp.SessionID,
		Reason:    "run_cancelled",
	}); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}

	families := mustGatherMetrics(t, registry)
	if got := metricValueWithLabels(families, "asb_sessions_active", map[string]string{"tenant": "t_acme"}); got != 0 {
		t.Fatalf("active sessions = %v, want 0", got)
	}
	if got := metricValueWithLabels(families, "asb_sessions_total", map[string]string{"outcome": "revoked"}); got != 1 {
		t.Fatalf("revoked sessions = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_grants_total", map[string]string{"outcome": "revoked"}); got != 1 {
		t.Fatalf("revoked grants = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_artifacts_active", map[string]string{"connector_kind": "github"}); got != 0 {
		t.Fatalf("active github artifacts = %v, want 0", got)
	}
	grant, err := repo.GetGrant(ctx, grantResp.GrantID)
	if err != nil {
		t.Fatalf("GetGrant() error = %v", err)
	}
	if grant.State != core.GrantStateRevoked {
		t.Fatalf("grant state = %q, want revoked", grant.State)
	}
}

func TestServiceMetrics_ExpireApprovalAndGrant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)
	registry := prometheus.NewRegistry()
	metrics, err := app.NewMetrics("asb", app.MetricsOptions{
		Registerer: registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	repo := memstore.NewRepository()
	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("evt_1"),
		Metrics:       metrics,
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: mustNewSigner(t),
		Policy:        stubPolicyEngine{},
		Tools:         stubToolRegistry{},
		Connectors:    fakeConnectorResolver{connector: &fakeConnector{kind: "browser"}},
		Audit:         memory.NewSink(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	if err := repo.SaveGrant(ctx, &core.Grant{
		ID:        "gr_pending",
		TenantID:  "t_acme",
		SessionID: "sess_pending",
		State:     core.GrantStatePending,
		CreatedAt: now.Add(-10 * time.Minute),
		ExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("SaveGrant() error = %v", err)
	}
	if err := repo.SaveApproval(ctx, &core.Approval{
		ID:          "ap_1",
		TenantID:    "t_acme",
		GrantID:     "gr_pending",
		RequestedBy: "browser_agent",
		State:       core.ApprovalStatePending,
		ExpiresAt:   now.Add(-1 * time.Minute),
		CreatedAt:   now.Add(-10 * time.Minute),
	}); err != nil {
		t.Fatalf("SaveApproval() error = %v", err)
	}

	if _, err := svc.RunCleanupOnce(ctx, 100); err != nil {
		t.Fatalf("RunCleanupOnce() error = %v", err)
	}

	families := mustGatherMetrics(t, registry)
	if got := metricValueWithLabels(families, "asb_approvals_total", map[string]string{"outcome": "expired"}); got != 1 {
		t.Fatalf("expired approvals = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_grants_total", map[string]string{"outcome": "expired"}); got != 1 {
		t.Fatalf("expired grants = %v, want 1", got)
	}
	if got := histogramCountWithLabels(families, "asb_approval_wait_seconds", map[string]string{"outcome": "expired"}); got != 1 {
		t.Fatalf("approval wait histogram count = %d, want 1", got)
	}
}

func TestServiceMetrics_PolicyEvaluationOutcomes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	registry := prometheus.NewRegistry()
	metrics, err := app.NewMetrics("asb", app.MetricsOptions{
		Registerer: registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	repo := memstore.NewRepository()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "github",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindProxyHandle,
			Metadata: map[string]string{
				"handle": "ph_policy_metrics",
			},
		},
	}
	delivery := &fakeDeliveryAdapter{
		mode: core.DeliveryModeProxy,
		delivery: &core.Delivery{
			Kind:   core.DeliveryKindProxyHandle,
			Handle: "ph_policy_metrics",
		},
	}

	mustPutTool(t, ctx, tools, core.Tool{
		TenantID:             "t_acme",
		Tool:                 "github",
		ManifestHash:         "sha256:test",
		RuntimeClass:         core.RuntimeClassHosted,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		AllowedCapabilities:  []string{"repo.read", "repo.write"},
		TrustTags:            []string{"trusted", "github"},
	})
	mustPutPolicy(t, engine, core.Policy{
		TenantID:             "t_acme",
		Capability:           "repo.read",
		ResourceKind:         core.ResourceKindGitHubRepo,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		DefaultTTL:           10 * time.Minute,
		MaxTTL:               10 * time.Minute,
		ApprovalMode:         core.ApprovalModeNone,
		RequiredToolTags:     []string{"trusted", "github"},
		Condition:            `true`,
	})

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("sess_policy_metrics", "evt_1", "gr_policy_metrics", "art_policy_metrics", "evt_2", "evt_3"),
		Metrics:       metrics,
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        engine,
		Tools:         tools,
		Connectors:    fakeConnectorResolver{connector: connector},
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeProxy: delivery,
		},
		Audit: memory.NewSink(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "agent_pr_reviewer",
		RunID:       "run_policy_metrics",
		ToolContext: []string{"github"},
		Attestation: &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if _, err := svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "github",
		Capability:   "repo.read",
		ResourceRef:  "github:repo:acme/widgets",
		DeliveryMode: core.DeliveryModeProxy,
	}); err != nil {
		t.Fatalf("RequestGrant(repo.read) error = %v", err)
	}
	if _, err := svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "github",
		Capability:   "repo.write",
		ResourceRef:  "github:repo:acme/widgets",
		DeliveryMode: core.DeliveryModeProxy,
	}); err == nil {
		t.Fatal("RequestGrant(repo.write) error = nil, want denied policy decision")
	}

	families := mustGatherMetrics(t, registry)
	if got := metricValueWithLabels(families, "asb_policy_evaluations_total", map[string]string{"capability": "repo.read", "outcome": "allowed"}); got != 1 {
		t.Fatalf("allowed policy evaluations = %v, want 1", got)
	}
	if got := metricValueWithLabels(families, "asb_policy_evaluations_total", map[string]string{"capability": "repo.write", "outcome": "denied"}); got != 1 {
		t.Fatalf("denied policy evaluations = %v, want 1", got)
	}
}

func TestServiceMetrics_BudgetExhaustion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	registry := prometheus.NewRegistry()
	metrics, err := app.NewMetrics("asb", app.MetricsOptions{
		Registerer: registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	repo := memstore.NewRepository()
	runtimeStore := memstore.NewRuntimeStore()
	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		Metrics:       metrics,
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: mustNewSigner(t),
		Policy:        stubPolicyEngine{},
		Tools:         stubToolRegistry{},
		Connectors:    fakeConnectorResolver{connector: &fakeConnector{kind: "github"}},
		Runtime:       runtimeStore,
		GitHubProxy:   &fakeGitHubProxyExecutor{payload: []byte(`{"ok":true}`)},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	session := &core.Session{
		ID:        "sess_budget_metrics",
		TenantID:  "t_acme",
		AgentID:   "agent_pr_reviewer",
		RunID:     "run_budget_metrics",
		State:     core.SessionStateActive,
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
	}
	artifactID := "art_budget_metrics"
	grant := &core.Grant{
		ID:          "gr_budget_metrics",
		TenantID:    "t_acme",
		SessionID:   session.ID,
		Tool:        "github",
		Capability:  "repo.read",
		ResourceRef: "github:repo:acme/widgets",
		State:       core.GrantStateIssued,
		ArtifactRef: &artifactID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
	}
	artifact := &core.Artifact{
		ID:            artifactID,
		TenantID:      "t_acme",
		SessionID:     session.ID,
		GrantID:       grant.ID,
		Handle:        "ph_budget_metrics",
		Kind:          core.ArtifactKindProxyHandle,
		ConnectorKind: "github",
		State:         core.ArtifactStateIssued,
		ExpiresAt:     now.Add(10 * time.Minute),
		CreatedAt:     now,
		Metadata: map[string]string{
			"operations": "pull_request_files",
		},
	}

	if err := repo.SaveSession(ctx, session); err != nil {
		t.Fatalf("SaveSession() error = %v", err)
	}
	if err := repo.SaveGrant(ctx, grant); err != nil {
		t.Fatalf("SaveGrant() error = %v", err)
	}
	if err := repo.SaveArtifact(ctx, artifact); err != nil {
		t.Fatalf("SaveArtifact() error = %v", err)
	}
	if err := runtimeStore.RegisterProxyHandle(ctx, artifact.Handle, core.ProxyBudget{MaxRequests: 1}, artifact.ExpiresAt); err != nil {
		t.Fatalf("RegisterProxyHandle() error = %v", err)
	}

	if _, err := svc.ExecuteGitHubProxy(ctx, &core.ExecuteGitHubProxyRequest{
		ProxyHandle: artifact.Handle,
		Operation:   "pull_request_files",
	}); err != nil {
		t.Fatalf("ExecuteGitHubProxy(first) error = %v", err)
	}
	if _, err := svc.ExecuteGitHubProxy(ctx, &core.ExecuteGitHubProxyRequest{
		ProxyHandle: artifact.Handle,
		Operation:   "pull_request_files",
	}); err == nil {
		t.Fatal("ExecuteGitHubProxy(second) error = nil, want budget exhaustion")
	}

	families := mustGatherMetrics(t, registry)
	if got := metricValueWithLabels(families, "asb_budget_exhaustion_total", map[string]string{"handle": "ph_budget_metrics"}); got != 1 {
		t.Fatalf("budget exhaustion count = %v, want 1", got)
	}
}

func TestServiceMetrics_UnwrapArtifact(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	registry := prometheus.NewRegistry()
	metrics, err := app.NewMetrics("asb", app.MetricsOptions{
		Registerer: registry,
	})
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	repo := memstore.NewRepository()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "vaultdb",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindWrappedSecret,
			SecretData: map[string]string{
				"username": "readonly",
				"password": "redacted",
			},
		},
	}
	delivery := &fakeDeliveryAdapter{
		mode: core.DeliveryModeWrappedSecret,
		delivery: &core.Delivery{
			Kind:       core.DeliveryKindWrappedSecret,
			ArtifactID: "art_unwrap_metrics",
		},
	}

	mustPutTool(t, ctx, tools, core.Tool{
		TenantID:             "t_acme",
		Tool:                 "vaultdb",
		ManifestHash:         "sha256:vaultdb",
		RuntimeClass:         core.RuntimeClassHosted,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
		AllowedCapabilities:  []string{"db.read"},
		TrustTags:            []string{"trusted", "db"},
	})
	mustPutPolicy(t, engine, core.Policy{
		TenantID:             "t_acme",
		Capability:           "db.read",
		ResourceKind:         core.ResourceKindDBRole,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
		DefaultTTL:           10 * time.Minute,
		MaxTTL:               10 * time.Minute,
		ApprovalMode:         core.ApprovalModeNone,
		RequiredToolTags:     []string{"trusted", "db"},
		Condition:            `true`,
	})

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("sess_unwrap_metrics", "evt_1", "gr_unwrap_metrics", "art_unwrap_metrics", "evt_2", "evt_3", "evt_4"),
		Metrics:       metrics,
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        engine,
		Tools:         tools,
		Connectors:    fakeConnectorResolver{connector: connector},
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeWrappedSecret: delivery,
		},
		Audit: memory.NewSink(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "agent_db_reader",
		RunID:       "run_unwrap_metrics",
		ToolContext: []string{"vaultdb"},
		Attestation: &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	grantResp, err := svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "vaultdb",
		Capability:   "db.read",
		ResourceRef:  "dbrole:analytics_readonly",
		DeliveryMode: core.DeliveryModeWrappedSecret,
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}

	if _, err := svc.UnwrapArtifact(ctx, &core.UnwrapArtifactRequest{
		SessionToken: sessionResp.SessionToken,
		ArtifactID:   grantResp.Delivery.ArtifactID,
	}); err != nil {
		t.Fatalf("UnwrapArtifact() error = %v", err)
	}

	families := mustGatherMetrics(t, registry)
	if got := metricValueWithLabels(families, "asb_artifacts_active", map[string]string{"connector_kind": "vaultdb"}); got != 0 {
		t.Fatalf("active vaultdb artifacts = %v, want 0", got)
	}
	if got := metricValueWithLabels(families, "asb_artifact_unwraps_total", map[string]string{"connector_kind": "vaultdb"}); got != 1 {
		t.Fatalf("vaultdb unwrap count = %v, want 1", got)
	}
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
