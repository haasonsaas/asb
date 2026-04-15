package app_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/evalops/asb/internal/app"
	"github.com/evalops/asb/internal/audit/memory"
	"github.com/evalops/asb/internal/authz/policy"
	"github.com/evalops/asb/internal/authz/toolregistry"
	"github.com/evalops/asb/internal/core"
	"github.com/evalops/asb/internal/crypto/sessionjwt"
	memstore "github.com/evalops/asb/internal/store/memory"
)

func TestService_CreateSessionAndIssueProxyGrant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	repo := memstore.NewRepository()
	auditSink := memory.NewSink()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "github",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindProxyHandle,
			Metadata: map[string]string{
				"handle": "ph_github_1",
			},
		},
	}
	delivery := &fakeDeliveryAdapter{
		mode: core.DeliveryModeProxy,
		delivery: &core.Delivery{
			Kind:   core.DeliveryKindProxyHandle,
			Handle: "ph_github_1",
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
		Condition:            `request.tool == "github" && resource.name == "acme/widgets" && session.agent_id == "agent_pr_reviewer"`,
	})

	svc, err := app.NewService(app.Config{
		Clock:               fixedClock(now),
		IDs:                 fixedIDs("sess_abc", "del_123", "gr_123", "art_123"),
		Repository:          repo,
		Verifier:            fakeVerifier{identity: workloadIdentity()},
		DelegationValidator: fakeDelegationValidator{delegation: repoReadDelegation(now)},
		SessionTokens:       signer,
		Policy:              engine,
		Tools:               tools,
		Connectors:          fakeConnectorResolver{connector: connector},
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeProxy: delivery,
		},
		ApprovalNotifier: noopApprovalNotifier{},
		Audit:            auditSink,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:            "t_acme",
		AgentID:             "agent_pr_reviewer",
		RunID:               "run_7f9",
		ToolContext:         []string{"github"},
		Attestation:         &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
		DelegationAssertion: "delegation",
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if sessionResp.SessionID != "sess_abc" {
		t.Fatalf("session id = %q, want %q", sessionResp.SessionID, "sess_abc")
	}
	if sessionResp.SessionToken == "" {
		t.Fatal("CreateSession() returned empty session token")
	}
	if got := sessionResp.ExpiresAt; !got.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("session expiry = %s, want %s", got, now.Add(15*time.Minute))
	}

	grantResp, err := svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "github",
		Capability:   "repo.read",
		ResourceRef:  "github:repo:acme/widgets",
		DeliveryMode: core.DeliveryModeProxy,
		TTL:          20 * time.Minute,
		Reason:       "fetch PR #142 files",
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if grantResp.State != core.GrantStateIssued {
		t.Fatalf("grant state = %q, want %q", grantResp.State, core.GrantStateIssued)
	}
	if grantResp.Delivery == nil || grantResp.Delivery.Handle != "ph_github_1" {
		t.Fatalf("delivery = %#v, want proxy handle", grantResp.Delivery)
	}
	if connector.issues != 1 {
		t.Fatalf("connector issues = %d, want 1", connector.issues)
	}

	storedGrant, err := repo.GetGrant(ctx, grantResp.GrantID)
	if err != nil {
		t.Fatalf("GetGrant() error = %v", err)
	}
	if storedGrant.EffectiveTTL != 10*time.Minute {
		t.Fatalf("effective ttl = %s, want %s", storedGrant.EffectiveTTL, 10*time.Minute)
	}
	if storedGrant.ApprovalID != nil {
		t.Fatalf("approval id = %v, want nil", *storedGrant.ApprovalID)
	}
	if got := len(auditSink.Events()); got < 3 {
		t.Fatalf("audit events = %d, want at least 3", got)
	}
}

func TestService_BrowserGrantRequiresApprovalBeforeIssue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
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
				"artifact_id": "art_browser_1",
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
			ArtifactID: "art_browser_1",
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
		IDs:           fixedIDs("sess_browser", "del_123", "gr_browser", "ap_browser", "art_browser_1"),
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
		RunID:       "run_42",
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
		Reason:       "log into vendor admin",
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if grantResp.State != core.GrantStatePending {
		t.Fatalf("grant state = %q, want %q", grantResp.State, core.GrantStatePending)
	}
	if grantResp.ApprovalID == "" {
		t.Fatal("pending grant missing approval id")
	}
	if connector.issues != 0 {
		t.Fatalf("connector issues before approval = %d, want 0", connector.issues)
	}

	approved, err := svc.ApproveGrant(ctx, &core.ApproveGrantRequest{
		ApprovalID: grantResp.ApprovalID,
		Approver:   "user:jonathan",
		Comment:    "expected browser login",
	})
	if err != nil {
		t.Fatalf("ApproveGrant() error = %v", err)
	}
	if approved.State != core.GrantStateIssued {
		t.Fatalf("approved state = %q, want %q", approved.State, core.GrantStateIssued)
	}
	if approved.Delivery == nil || approved.Delivery.ArtifactID != "art_browser_1" {
		t.Fatalf("delivery after approval = %#v, want wrapped artifact", approved.Delivery)
	}
	if connector.issues != 1 {
		t.Fatalf("connector issues after approval = %d, want 1", connector.issues)
	}
}

func TestService_RequestGrantMintedTokenReturnsNotImplementedBeforePersistingApproval(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	repo := memstore.NewRepository()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "github",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindMintedToken,
			SecretData: map[string]string{
				"token": "ghs_test",
			},
		},
	}

	mustPutTool(t, ctx, tools, core.Tool{
		TenantID:             "t_acme",
		Tool:                 "github",
		ManifestHash:         "sha256:minted",
		RuntimeClass:         core.RuntimeClassHosted,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeMintedToken},
		AllowedCapabilities:  []string{"repo.read"},
		TrustTags:            []string{"trusted", "github"},
	})
	mustPutPolicy(t, engine, core.Policy{
		TenantID:             "t_acme",
		Capability:           "repo.read",
		ResourceKind:         core.ResourceKindGitHubRepo,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeMintedToken},
		DefaultTTL:           2 * time.Minute,
		MaxTTL:               5 * time.Minute,
		ApprovalMode:         core.ApprovalModeLiveHuman,
		RequiredToolTags:     []string{"trusted", "github"},
		Condition:            `true`,
	})

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("sess_minted", "evt_session"),
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        engine,
		Tools:         tools,
		Connectors:    fakeConnectorResolver{connector: connector},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "agent_pr_reviewer",
		RunID:       "run_minted",
		ToolContext: []string{"github"},
		Attestation: &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	_, err = svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "github",
		Capability:   "repo.read",
		ResourceRef:  "github:repo:acme/widgets",
		DeliveryMode: core.DeliveryModeMintedToken,
		TTL:          5 * time.Minute,
		Reason:       "mint direct token",
	})
	if err == nil {
		t.Fatal("RequestGrant() error = nil, want non-nil")
	}
	if !errors.Is(err, core.ErrDeliveryModeNotImplemented) {
		t.Fatalf("RequestGrant() error = %v, want ErrDeliveryModeNotImplemented", err)
	}
	if !strings.Contains(err.Error(), "validate delivery mode") {
		t.Fatalf("RequestGrant() error = %q, want delivery-mode context", err)
	}
	if connector.issues != 0 {
		t.Fatalf("connector issues = %d, want 0", connector.issues)
	}

	grants, err := repo.ListGrantsBySession(ctx, sessionResp.SessionID)
	if err != nil {
		t.Fatalf("ListGrantsBySession() error = %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("grants = %d, want 0", len(grants))
	}
	if _, err := repo.GetApproval(ctx, "ap_minted"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("GetApproval() error = %v, want ErrNotFound", err)
	}
}

func TestService_ApproveGrantMintedTokenReturnsNotImplementedWithoutMutatingApproval(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	repo := memstore.NewRepository()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "github",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindMintedToken,
			SecretData: map[string]string{
				"token": "ghs_test",
			},
		},
	}

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        stubPolicyEngine{},
		Tools:         stubToolRegistry{},
		Connectors:    fakeConnectorResolver{connector: connector},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	session := &core.Session{
		ID:        "sess_pending_minted",
		TenantID:  "t_acme",
		AgentID:   "agent_pr_reviewer",
		RunID:     "run_pending_minted",
		State:     core.SessionStateActive,
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
	}
	approvalID := "ap_pending_minted"
	grant := &core.Grant{
		ID:           "gr_pending_minted",
		TenantID:     "t_acme",
		SessionID:    session.ID,
		Tool:         "github",
		Capability:   "repo.read",
		ResourceRef:  "github:repo:acme/widgets",
		DeliveryMode: core.DeliveryModeMintedToken,
		ApprovalID:   &approvalID,
		State:        core.GrantStatePending,
		CreatedAt:    now,
		ExpiresAt:    now.Add(10 * time.Minute),
	}
	approval := &core.Approval{
		ID:          approvalID,
		TenantID:    "t_acme",
		GrantID:     grant.ID,
		RequestedBy: "agent_pr_reviewer",
		State:       core.ApprovalStatePending,
		ExpiresAt:   now.Add(5 * time.Minute),
		CreatedAt:   now,
	}
	if err := repo.SaveSession(ctx, session); err != nil {
		t.Fatalf("SaveSession() error = %v", err)
	}
	if err := repo.SaveGrant(ctx, grant); err != nil {
		t.Fatalf("SaveGrant() error = %v", err)
	}
	if err := repo.SaveApproval(ctx, approval); err != nil {
		t.Fatalf("SaveApproval() error = %v", err)
	}

	_, err = svc.ApproveGrant(ctx, &core.ApproveGrantRequest{
		ApprovalID: approval.ID,
		Approver:   "user:jonathan",
		Comment:    "ship it",
	})
	if err == nil {
		t.Fatal("ApproveGrant() error = nil, want non-nil")
	}
	if !errors.Is(err, core.ErrDeliveryModeNotImplemented) {
		t.Fatalf("ApproveGrant() error = %v, want ErrDeliveryModeNotImplemented", err)
	}
	if connector.issues != 0 {
		t.Fatalf("connector issues = %d, want 0", connector.issues)
	}

	storedApproval, err := repo.GetApproval(ctx, approval.ID)
	if err != nil {
		t.Fatalf("GetApproval() error = %v", err)
	}
	if storedApproval.State != core.ApprovalStatePending {
		t.Fatalf("approval state = %q, want %q", storedApproval.State, core.ApprovalStatePending)
	}
	if storedApproval.ApprovedBy != nil {
		t.Fatalf("approved_by = %v, want nil", *storedApproval.ApprovedBy)
	}
}

func TestService_RevokeSessionRevokesOutstandingGrants(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	repo := memstore.NewRepository()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "github",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindProxyHandle,
			Metadata: map[string]string{
				"handle": "ph_github_2",
			},
		},
	}
	delivery := &fakeDeliveryAdapter{
		mode: core.DeliveryModeProxy,
		delivery: &core.Delivery{
			Kind:   core.DeliveryKindProxyHandle,
			Handle: "ph_github_2",
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
		IDs:           fixedIDs("sess_rev", "gr_rev", "art_rev"),
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
		RunID:       "run_7f9",
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
		Reason:       "fetch repo metadata",
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

	grant, err := repo.GetGrant(ctx, grantResp.GrantID)
	if err != nil {
		t.Fatalf("GetGrant() error = %v", err)
	}
	if grant.State != core.GrantStateRevoked {
		t.Fatalf("grant state after revoke = %q, want %q", grant.State, core.GrantStateRevoked)
	}
	if connector.revocations != 1 {
		t.Fatalf("connector revocations = %d, want 1", connector.revocations)
	}
}

func mustNewSigner(t *testing.T) core.SessionTokenManager {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	signer, err := sessionjwt.NewManager(privateKey)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	return signer
}

func testNow() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

func mustPutTool(t *testing.T, ctx context.Context, registry *toolregistry.Registry, tool core.Tool) {
	t.Helper()
	if err := registry.Put(ctx, tool); err != nil {
		t.Fatalf("registry.Put() error = %v", err)
	}
}

func mustPutPolicy(t *testing.T, engine *policy.Engine, pol core.Policy) {
	t.Helper()
	if err := engine.Put(pol); err != nil {
		t.Fatalf("engine.Put() error = %v", err)
	}
}

func workloadIdentity() *core.WorkloadIdentity {
	return &core.WorkloadIdentity{
		Type:           core.WorkloadIdentityTypeK8SSA,
		Issuer:         "https://cluster.example",
		Subject:        "system:serviceaccount:agents:runner",
		Audience:       "asb-control-plane",
		Namespace:      "agents",
		ServiceAccount: "runner",
		Attributes: map[string]string{
			"pod_uid": "pod_123",
		},
	}
}

func repoReadDelegation(now time.Time) *core.Delegation {
	return &core.Delegation{
		ID:                  "del_123",
		Issuer:              "app.evalops.example",
		Subject:             "user:jonathan",
		TenantID:            "t_acme",
		AgentID:             "agent_pr_reviewer",
		AllowedCapabilities: []string{"repo.read"},
		ResourceFilters: map[string][]string{
			"repo": []string{"acme/widgets"},
		},
		ExpiresAt: now.Add(10 * time.Minute),
	}
}

type fakeVerifier struct {
	identity *core.WorkloadIdentity
	err      error
}

func (f fakeVerifier) Verify(context.Context, *core.Attestation) (*core.WorkloadIdentity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.identity, nil
}

type fakeDelegationValidator struct {
	delegation *core.Delegation
	err        error
}

func (f fakeDelegationValidator) Validate(context.Context, string, string, string) (*core.Delegation, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.delegation, nil
}

type fakeConnectorResolver struct {
	connector core.Connector
	err       error
}

func (f fakeConnectorResolver) Resolve(context.Context, string, string) (core.Connector, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.connector, nil
}

type fakeConnector struct {
	kind        string
	issued      *core.IssuedArtifact
	validateErr error
	issueErr    error
	revokeErr   error
	issues      int
	revocations int
}

func (f *fakeConnector) Kind() string {
	return f.kind
}

func (f *fakeConnector) ValidateResource(context.Context, core.ValidateResourceRequest) error {
	return f.validateErr
}

func (f *fakeConnector) Issue(context.Context, core.IssueRequest) (*core.IssuedArtifact, error) {
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	f.issues++
	return f.issued, nil
}

func (f *fakeConnector) Revoke(context.Context, core.RevokeRequest) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revocations++
	return nil
}

type fakeDeliveryAdapter struct {
	mode     core.DeliveryMode
	delivery *core.Delivery
	err      error
}

func (f *fakeDeliveryAdapter) Mode() core.DeliveryMode {
	return f.mode
}

func (f *fakeDeliveryAdapter) Deliver(context.Context, *core.IssuedArtifact, *core.Session, *core.Grant) (*core.Delivery, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.delivery, nil
}

type noopApprovalNotifier struct{}

func (noopApprovalNotifier) NotifyPending(context.Context, *core.ApprovalCallbackConfig, *core.Approval, *core.Grant) error {
	return nil
}

type fixedClock time.Time

func (c fixedClock) Now() time.Time {
	return time.Time(c)
}

type fixedIDGen struct {
	values []string
	index  int
}

func (g *fixedIDGen) New(prefix string) string {
	if g.index >= len(g.values) {
		return prefix + "_missing"
	}
	value := g.values[g.index]
	g.index++
	return value
}

func fixedIDs(values ...string) *fixedIDGen {
	return &fixedIDGen{values: values}
}

func TestFixedIDs(t *testing.T) {
	t.Parallel()

	ids := fixedIDs("a", "b")
	if got := ids.New("x"); got != "a" {
		t.Fatalf("first id = %q, want %q", got, "a")
	}
	if got := ids.New("x"); got != "b" {
		t.Fatalf("second id = %q, want %q", got, "b")
	}
}

func TestFakeConnectorResolverError(t *testing.T) {
	t.Parallel()

	resolver := fakeConnectorResolver{err: errors.New("boom")}
	if _, err := resolver.Resolve(context.Background(), "repo.read", "github:repo:acme/widgets"); err == nil {
		t.Fatal("Resolve() error = nil, want non-nil")
	}
}
