package app_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/evalops/asb/internal/app"
	"github.com/evalops/asb/internal/core"
	memstore "github.com/evalops/asb/internal/store/memory"
)

func TestService_ApproveGrantExpiredApprovalReturnsSaveError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	baseRepo := memstore.NewRepository()
	saveErr := errors.New("save approval boom")
	repo := interceptRepository{
		Repository: baseRepo,
		saveApproval: func(ctx context.Context, approval *core.Approval) error {
			if approval.ID == "ap_expired" && approval.State == core.ApprovalStateExpired {
				return saveErr
			}
			return baseRepo.SaveApproval(ctx, approval)
		},
	}

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("evt_1"),
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: mustNewSigner(t),
		Policy:        stubPolicyEngine{},
		Tools:         stubToolRegistry{},
		Connectors:    fakeConnectorResolver{connector: &fakeConnector{kind: "browser"}},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	session := &core.Session{
		ID:        "sess_expired_approval",
		TenantID:  "t_acme",
		AgentID:   "browser_agent",
		RunID:     "run_approval",
		State:     core.SessionStateActive,
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
	}
	grant := &core.Grant{
		ID:        "gr_expired_approval",
		TenantID:  "t_acme",
		SessionID: session.ID,
		State:     core.GrantStatePending,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	approval := &core.Approval{
		ID:          "ap_expired",
		TenantID:    "t_acme",
		GrantID:     grant.ID,
		RequestedBy: "browser_agent",
		State:       core.ApprovalStatePending,
		ExpiresAt:   now.Add(-1 * time.Minute),
		CreatedAt:   now.Add(-10 * time.Minute),
	}

	if err := baseRepo.SaveSession(ctx, session); err != nil {
		t.Fatalf("SaveSession() error = %v", err)
	}
	if err := baseRepo.SaveGrant(ctx, grant); err != nil {
		t.Fatalf("SaveGrant() error = %v", err)
	}
	if err := baseRepo.SaveApproval(ctx, approval); err != nil {
		t.Fatalf("SaveApproval() error = %v", err)
	}

	_, err = svc.ApproveGrant(ctx, &core.ApproveGrantRequest{
		ApprovalID: approval.ID,
		Approver:   "user:jonathan",
	})
	if err == nil {
		t.Fatal("ApproveGrant() error = nil, want non-nil")
	}
	if !errors.Is(err, saveErr) {
		t.Fatalf("ApproveGrant() error = %v, want wrapped save error", err)
	}
	if !strings.Contains(err.Error(), "expire approval") {
		t.Fatalf("ApproveGrant() error = %q, want context about expiring approval", err)
	}
}

func TestService_RequestGrantExpiredSessionReturnsSaveError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	baseRepo := memstore.NewRepository()
	saveErr := errors.New("save session boom")
	repo := interceptRepository{
		Repository: baseRepo,
		saveSession: func(ctx context.Context, session *core.Session) error {
			if session.ID == "sess_expired" && session.State == core.SessionStateExpired {
				return saveErr
			}
			return baseRepo.SaveSession(ctx, session)
		},
	}
	signer := mustNewSigner(t)

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        stubPolicyEngine{},
		Tools:         stubToolRegistry{},
		Connectors:    fakeConnectorResolver{connector: &fakeConnector{kind: "github"}},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	session := &core.Session{
		ID:        "sess_expired",
		TenantID:  "t_acme",
		AgentID:   "agent_pr_reviewer",
		RunID:     "run_expired",
		State:     core.SessionStateActive,
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now.Add(-time.Hour),
	}
	if err := baseRepo.SaveSession(ctx, session); err != nil {
		t.Fatalf("SaveSession() error = %v", err)
	}
	token, err := signer.Sign(session)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	session.ExpiresAt = now.Add(-1 * time.Minute)
	if err := baseRepo.SaveSession(ctx, session); err != nil {
		t.Fatalf("SaveSession() error = %v", err)
	}

	_, err = svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: token,
		Tool:         "github",
		Capability:   "repo.read",
		ResourceRef:  "github:repo:acme/widgets",
		DeliveryMode: core.DeliveryModeProxy,
	})
	if err == nil {
		t.Fatal("RequestGrant() error = nil, want non-nil")
	}
	if !errors.Is(err, saveErr) {
		t.Fatalf("RequestGrant() error = %v, want wrapped save error", err)
	}
	if !strings.Contains(err.Error(), "expire session") {
		t.Fatalf("RequestGrant() error = %q, want context about expiring session", err)
	}
}

func TestService_ExecuteGitHubProxyLogsBestEffortBudgetReleaseFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	baseRepo := memstore.NewRepository()
	baseRuntime := memstore.NewRuntimeStore()
	logger, logs := newTestLogger()
	execErr := errors.New("upstream boom")
	releaseErr := errors.New("release budget boom")
	runtime := interceptRuntimeStore{
		RuntimeStore: baseRuntime,
		completeProxyRequest: func(context.Context, string, int64) error {
			return releaseErr
		},
	}

	svc, err := app.NewService(app.Config{
		Logger:        logger,
		Clock:         fixedClock(now),
		Repository:    baseRepo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: mustNewSigner(t),
		Policy:        stubPolicyEngine{},
		Tools:         stubToolRegistry{},
		Connectors:    fakeConnectorResolver{connector: &fakeConnector{kind: "github"}},
		Runtime:       runtime,
		GitHubProxy:   &fakeGitHubProxyExecutor{err: execErr},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	session := &core.Session{
		ID:        "sess_proxy",
		TenantID:  "t_acme",
		AgentID:   "agent_pr_reviewer",
		RunID:     "run_proxy",
		State:     core.SessionStateActive,
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
	}
	artifactID := "art_proxy"
	grant := &core.Grant{
		ID:          "gr_proxy",
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
		Handle:        "ph_proxy",
		Kind:          core.ArtifactKindProxyHandle,
		ConnectorKind: "github",
		State:         core.ArtifactStateIssued,
		ExpiresAt:     now.Add(10 * time.Minute),
		CreatedAt:     now,
		Metadata: map[string]string{
			"operations": "pull_request_files",
		},
	}
	if err := baseRepo.SaveSession(ctx, session); err != nil {
		t.Fatalf("SaveSession() error = %v", err)
	}
	if err := baseRepo.SaveGrant(ctx, grant); err != nil {
		t.Fatalf("SaveGrant() error = %v", err)
	}
	if err := baseRepo.SaveArtifact(ctx, artifact); err != nil {
		t.Fatalf("SaveArtifact() error = %v", err)
	}
	if err := baseRuntime.RegisterProxyHandle(ctx, artifact.Handle, core.ProxyBudget{}, artifact.ExpiresAt); err != nil {
		t.Fatalf("RegisterProxyHandle() error = %v", err)
	}

	_, err = svc.ExecuteGitHubProxy(ctx, &core.ExecuteGitHubProxyRequest{
		ProxyHandle: artifact.Handle,
		Operation:   "pull_request_files",
	})
	if err == nil {
		t.Fatal("ExecuteGitHubProxy() error = nil, want non-nil")
	}
	if !errors.Is(err, execErr) {
		t.Fatalf("ExecuteGitHubProxy() error = %v, want wrapped upstream error", err)
	}
	if !strings.Contains(logs.String(), "complete proxy request budget release failed") {
		t.Fatalf("logs = %q, want deferred cleanup warning", logs.String())
	}
}

func TestService_CreateSessionLogsAuditAppendFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	logger, logs := newTestLogger()

	svc, err := app.NewService(app.Config{
		Logger:        logger,
		Clock:         fixedClock(now),
		Repository:    memstore.NewRepository(),
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: mustNewSigner(t),
		Policy:        stubPolicyEngine{},
		Tools:         stubToolRegistry{},
		Connectors:    fakeConnectorResolver{connector: &fakeConnector{kind: "github"}},
		Audit:         failingAuditSink{err: errors.New("audit append boom")},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	resp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "agent_pr_reviewer",
		RunID:       "run_audit",
		ToolContext: []string{"github"},
		Attestation: &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if resp.SessionID == "" {
		t.Fatal("CreateSession() returned empty session id")
	}
	if !strings.Contains(logs.String(), "audit append failed") {
		t.Fatalf("logs = %q, want audit warning", logs.String())
	}
}

type interceptRepository struct {
	core.Repository
	saveSession  func(context.Context, *core.Session) error
	saveApproval func(context.Context, *core.Approval) error
}

func (r interceptRepository) SaveSession(ctx context.Context, session *core.Session) error {
	if r.saveSession != nil {
		return r.saveSession(ctx, session)
	}
	return r.Repository.SaveSession(ctx, session)
}

func (r interceptRepository) SaveApproval(ctx context.Context, approval *core.Approval) error {
	if r.saveApproval != nil {
		return r.saveApproval(ctx, approval)
	}
	return r.Repository.SaveApproval(ctx, approval)
}

type interceptRuntimeStore struct {
	core.RuntimeStore
	completeProxyRequest func(context.Context, string, int64) error
}

func (r interceptRuntimeStore) CompleteProxyRequest(ctx context.Context, handle string, responseBytes int64) error {
	if r.completeProxyRequest != nil {
		return r.completeProxyRequest(ctx, handle, responseBytes)
	}
	return r.RuntimeStore.CompleteProxyRequest(ctx, handle, responseBytes)
}

type failingAuditSink struct {
	err error
}

func (s failingAuditSink) Append(context.Context, *core.AuditEvent) error {
	return s.err
}

func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, &buf
}
