package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/haasonsaas/asb/internal/app"
	"github.com/haasonsaas/asb/internal/audit/memory"
	"github.com/haasonsaas/asb/internal/authz/policy"
	"github.com/haasonsaas/asb/internal/authz/toolregistry"
	"github.com/haasonsaas/asb/internal/core"
	proxydelivery "github.com/haasonsaas/asb/internal/delivery/proxy"
	wrappeddelivery "github.com/haasonsaas/asb/internal/delivery/wrapped"
	memstore "github.com/haasonsaas/asb/internal/store/memory"
)

func TestService_ExecuteGitHubProxy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	repo := memstore.NewRepository()
	runtime := memstore.NewRuntimeStore()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "github",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindProxyHandle,
			Metadata: map[string]string{
				"handle":          "ph_exec_1",
				"operations":      "pull_request_files",
				"max_concurrent":  "8",
				"max_requests":    "100",
				"max_bytes":       "1024",
				"timeout_seconds": "15",
			},
		},
	}
	executor := &fakeGitHubProxyExecutor{
		payload: []byte(`{"files":[{"filename":"main.go"}]}`),
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
		Condition:            `request.tool == "github"`,
	})

	svc, err := app.NewService(app.Config{
		Clock:         fixedClock(now),
		IDs:           fixedIDs("sess_exec", "evt_a", "evt_b", "gr_exec", "evt_c", "art_exec", "evt_d", "evt_e", "evt_f"),
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        engine,
		Tools:         tools,
		Connectors:    fakeConnectorResolver{connector: connector},
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeProxy: proxydelivery.NewAdapter(),
		},
		Audit:       memory.NewSink(),
		Runtime:     runtime,
		GitHubProxy: executor,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "agent_pr_reviewer",
		RunID:       "run_exec",
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
		Reason:       "fetch files",
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if grantResp.Delivery == nil || grantResp.Delivery.Handle != "ph_exec_1" {
		t.Fatalf("delivery = %#v, want proxy handle", grantResp.Delivery)
	}

	resp, err := svc.ExecuteGitHubProxy(ctx, &core.ExecuteGitHubProxyRequest{
		ProxyHandle: "ph_exec_1",
		Operation:   "pull_request_files",
		Params: map[string]any{
			"owner":       "acme",
			"repo":        "widgets",
			"pull_number": 142,
		},
	})
	if err != nil {
		t.Fatalf("ExecuteGitHubProxy() error = %v", err)
	}
	if string(resp.Payload) != `{"files":[{"filename":"main.go"}]}` {
		t.Fatalf("payload = %s, want expected json", string(resp.Payload))
	}
	if executor.calls != 1 {
		t.Fatalf("executor calls = %d, want 1", executor.calls)
	}
}

func TestService_RegisterBrowserRelayAndUnwrapArtifact(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := testNow()
	repo := memstore.NewRepository()
	runtime := memstore.NewRuntimeStore()
	tools := toolregistry.New()
	engine := policy.NewEngine()
	signer := mustNewSigner(t)
	connector := &fakeConnector{
		kind: "browser",
		issued: &core.IssuedArtifact{
			Kind: core.ArtifactKindWrappedSecret,
			Metadata: map[string]string{
				"artifact_id":       "art_browser_real",
				"origin":            "https://admin.vendor.example",
				"selector_username": "#username",
				"selector_password": "#password",
			},
			SecretData: map[string]string{
				"username": "admin",
				"password": "hunter2",
			},
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
		IDs:           fixedIDs("sess_browser", "evt1", "gr_browser", "evt2", "ap_browser", "evt3", "evt4", "evt5", "evt6", "evt7"),
		Repository:    repo,
		Verifier:      fakeVerifier{identity: workloadIdentity()},
		SessionTokens: signer,
		Policy:        engine,
		Tools:         tools,
		Connectors:    fakeConnectorResolver{connector: connector},
		Deliveries: map[core.DeliveryMode]core.DeliveryAdapter{
			core.DeliveryModeWrappedSecret: wrappeddelivery.NewAdapter(),
		},
		Audit:   memory.NewSink(),
		Runtime: runtime,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	sessionResp, err := svc.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    "t_acme",
		AgentID:     "browser_agent",
		RunID:       "run_browser",
		ToolContext: []string{"browser"},
		Attestation: &core.Attestation{Kind: core.AttestationKindK8SServiceAccountJWT, Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if _, err := svc.RegisterBrowserRelay(ctx, &core.RegisterBrowserRelayRequest{
		SessionToken: sessionResp.SessionToken,
		KeyID:        "key_1",
		PublicKey:    "pubkey",
		Origin:       "https://admin.vendor.example",
		TabID:        "tab_42",
		Selectors: map[string]string{
			"username": "#username",
			"password": "#password",
		},
	}); err != nil {
		t.Fatalf("RegisterBrowserRelay() error = %v", err)
	}

	grantResp, err := svc.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: sessionResp.SessionToken,
		Tool:         "browser",
		Capability:   "browser.login",
		ResourceRef:  "browser_origin:https://admin.vendor.example",
		DeliveryMode: core.DeliveryModeWrappedSecret,
		TTL:          5 * time.Minute,
		Reason:       "login",
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	issued, err := svc.ApproveGrant(ctx, &core.ApproveGrantRequest{
		ApprovalID: grantResp.ApprovalID,
		Approver:   "user:jonathan",
		Comment:    "approved",
	})
	if err != nil {
		t.Fatalf("ApproveGrant() error = %v", err)
	}

	unwrapped, err := svc.UnwrapArtifact(ctx, &core.UnwrapArtifactRequest{
		SessionToken: sessionResp.SessionToken,
		ArtifactID:   issued.Delivery.ArtifactID,
		KeyID:        "key_1",
		Origin:       "https://admin.vendor.example",
		TabID:        "tab_42",
	})
	if err != nil {
		t.Fatalf("UnwrapArtifact() error = %v", err)
	}
	if len(unwrapped.Fields) != 2 {
		t.Fatalf("fields len = %d, want 2", len(unwrapped.Fields))
	}
	if unwrapped.AutoSubmit {
		t.Fatal("AutoSubmit = true, want false")
	}

	if _, err := svc.UnwrapArtifact(ctx, &core.UnwrapArtifactRequest{
		SessionToken: sessionResp.SessionToken,
		ArtifactID:   issued.Delivery.ArtifactID,
		KeyID:        "key_1",
		Origin:       "https://admin.vendor.example",
		TabID:        "tab_42",
	}); err == nil {
		t.Fatal("second UnwrapArtifact() error = nil, want single-use failure")
	}
}

type fakeGitHubProxyExecutor struct {
	payload []byte
	err     error
	calls   int
}

func (f *fakeGitHubProxyExecutor) Execute(context.Context, *core.Artifact, string, map[string]any) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.calls++
	return f.payload, nil
}
