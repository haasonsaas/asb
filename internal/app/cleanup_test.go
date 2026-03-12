package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/haasonsaas/asb/internal/app"
	"github.com/haasonsaas/asb/internal/audit/memory"
	"github.com/haasonsaas/asb/internal/core"
	memstore "github.com/haasonsaas/asb/internal/store/memory"
)

func TestService_RunCleanupOnceExpiresSessionsAndArtifacts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)
	repo := memstore.NewRepository()
	connector := &fakeConnector{kind: "github"}

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("evt1", "evt2", "evt3"),
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: mustNewSigner(t),
		Policy:        stubPolicyEngine{},
		Tools:         stubToolRegistry{},
		Connectors:    fakeConnectorResolver{connector: connector},
		Audit:         memory.NewSink(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	session := &core.Session{
		ID:        "sess_1",
		TenantID:  "t_acme",
		AgentID:   "agent_pr_reviewer",
		RunID:     "run_1",
		State:     core.SessionStateActive,
		ExpiresAt: now.Add(-1 * time.Minute),
		CreatedAt: now.Add(-2 * time.Hour),
	}
	grant := &core.Grant{
		ID:            "gr_1",
		TenantID:      "t_acme",
		SessionID:     "sess_1",
		Tool:          "github",
		Capability:    "repo.read",
		ResourceRef:   "github:repo:acme/widgets",
		DeliveryMode:  core.DeliveryModeProxy,
		ConnectorKind: "github",
		State:         core.GrantStateIssued,
		ExpiresAt:     now.Add(5 * time.Minute),
		CreatedAt:     now.Add(-time.Hour),
	}
	artifactID := "art_1"
	grant.ArtifactRef = &artifactID
	artifact := &core.Artifact{
		ID:            artifactID,
		TenantID:      "t_acme",
		SessionID:     "sess_1",
		GrantID:       "gr_1",
		Handle:        "ph_1",
		Kind:          core.ArtifactKindProxyHandle,
		ConnectorKind: "github",
		State:         core.ArtifactStateIssued,
		ExpiresAt:     now.Add(5 * time.Minute),
		CreatedAt:     now.Add(-time.Hour),
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

	stats, err := svc.RunCleanupOnce(ctx, 100)
	if err != nil {
		t.Fatalf("RunCleanupOnce() error = %v", err)
	}
	if stats.SessionsExpired != 1 || stats.GrantsExpired != 1 {
		t.Fatalf("stats = %#v, want one expired session and grant", stats)
	}
	if connector.revocations != 1 {
		t.Fatalf("connector revocations = %d, want 1", connector.revocations)
	}

	storedSession, _ := repo.GetSession(ctx, "sess_1")
	if storedSession.State != core.SessionStateExpired {
		t.Fatalf("session state = %q, want expired", storedSession.State)
	}
	storedGrant, _ := repo.GetGrant(ctx, "gr_1")
	if storedGrant.State != core.GrantStateExpired {
		t.Fatalf("grant state = %q, want expired", storedGrant.State)
	}
	storedArtifact, _ := repo.GetArtifact(ctx, artifactID)
	if storedArtifact.State != core.ArtifactStateExpired {
		t.Fatalf("artifact state = %q, want expired", storedArtifact.State)
	}
}

func TestService_RunCleanupOnceExpiresPendingApprovals(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)
	repo := memstore.NewRepository()

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("evt1"),
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

	stats, err := svc.RunCleanupOnce(ctx, 100)
	if err != nil {
		t.Fatalf("RunCleanupOnce() error = %v", err)
	}
	if stats.ApprovalsExpired != 1 {
		t.Fatalf("stats = %#v, want one expired approval", stats)
	}
	approval, _ := repo.GetApproval(ctx, "ap_1")
	if approval.State != core.ApprovalStateExpired {
		t.Fatalf("approval state = %q, want expired", approval.State)
	}
	grant, _ := repo.GetGrant(ctx, "gr_pending")
	if grant.State != core.GrantStateExpired {
		t.Fatalf("grant state = %q, want expired", grant.State)
	}
}

type stubPolicyEngine struct{}

func (stubPolicyEngine) Evaluate(context.Context, *core.DecisionInput) (*core.Decision, error) {
	return &core.Decision{Allowed: true}, nil
}

type stubToolRegistry struct{}

func (stubToolRegistry) Put(context.Context, core.Tool) error { return nil }

func (stubToolRegistry) Get(context.Context, string, string) (*core.Tool, error) {
	return &core.Tool{}, nil
}
