package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/evalops/asb/internal/api/httpapi"
	"github.com/evalops/asb/internal/core"
	"github.com/evalops/service-runtime/ratelimit"
)

func TestServer_CreateSession(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		createSession: func(_ context.Context, req *core.CreateSessionRequest) (*core.CreateSessionResponse, error) {
			if req.TenantID != "t_acme" || req.AgentID != "agent_pr_reviewer" {
				t.Fatalf("unexpected create session request: %#v", req)
			}
			return &core.CreateSessionResponse{
				SessionID:    "sess_abc",
				SessionToken: "eyJ.test",
				ExpiresAt:    time.Date(2026, 3, 12, 20, 15, 0, 0, time.UTC),
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewBufferString(`{
		"tenant_id":"t_acme",
		"agent_id":"agent_pr_reviewer",
		"run_id":"run_7f9",
		"tool_context":["github"],
		"attestation":{"kind":"k8s_sa_jwt","token":"jwt"},
		"delegation_assertion":"signed"
	}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(svc).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if payload["session_id"] != "sess_abc" {
		t.Fatalf("session_id = %v, want sess_abc", payload["session_id"])
	}
	if payload["session_token"] != "eyJ.test" {
		t.Fatalf("session_token = %v, want eyJ.test", payload["session_token"])
	}
}

func TestServer_RequestGrant(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		requestGrant: func(_ context.Context, req *core.RequestGrantRequest) (*core.RequestGrantResponse, error) {
			if req.TTL != 10*time.Minute {
				t.Fatalf("TTL = %s, want %s", req.TTL, 10*time.Minute)
			}
			return &core.RequestGrantResponse{
				GrantID: "gr_123",
				State:   core.GrantStateIssued,
				Delivery: &core.Delivery{
					Kind:   core.DeliveryKindProxyHandle,
					Handle: "ph_456",
				},
				ExpiresAt: time.Date(2026, 3, 12, 20, 10, 0, 0, time.UTC),
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewBufferString(`{
		"session_token":"eyJ.test",
		"tool":"github",
		"capability":"repo.read",
		"resource_ref":"github:repo:acme/widgets",
		"delivery_mode":"proxy",
		"ttl_seconds":600,
		"reason":"fetch pr files"
	}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(svc).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if payload["grant_id"] != "gr_123" {
		t.Fatalf("grant_id = %v, want gr_123", payload["grant_id"])
	}
}

func TestServer_RejectsUnsupportedContentType(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(&stubService{}).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnsupportedMediaType)
	}
}

func TestServer_RejectsOversizedBody(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewBufferString(`{"tenant_id":"`+strings.Repeat("a", 256)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(&stubService{}, httpapi.WithMaxBodyBytes(32)).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestServer_RequestTimeoutReturnsGatewayTimeout(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		createSession: func(ctx context.Context, req *core.CreateSessionRequest) (*core.CreateSessionResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewBufferString(`{
		"tenant_id":"t_acme",
		"agent_id":"agent_pr_reviewer",
		"run_id":"run_7f9",
		"tool_context":["github"],
		"attestation":{"kind":"k8s_sa_jwt","token":"jwt"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(svc, httpapi.WithRequestTimeouts(time.Nanosecond, time.Nanosecond, time.Nanosecond)).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusGatewayTimeout)
	}
}

func TestServer_ServiceContextRemainsAliveAfterDecode(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		createSession: func(ctx context.Context, req *core.CreateSessionRequest) (*core.CreateSessionResponse, error) {
			if err := ctx.Err(); err != nil {
				t.Fatalf("context canceled before service call: %v", err)
			}
			return &core.CreateSessionResponse{
				SessionID:    "sess_abc",
				SessionToken: "eyJ.test",
				ExpiresAt:    time.Date(2026, 3, 12, 20, 15, 0, 0, time.UTC),
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewBufferString(`{
		"tenant_id":"t_acme",
		"agent_id":"agent_pr_reviewer",
		"run_id":"run_7f9",
		"tool_context":["github"],
		"attestation":{"kind":"k8s_sa_jwt","token":"jwt"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(svc, httpapi.WithRequestTimeouts(time.Second, time.Second, time.Second)).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestServer_RejectsTrailingJSONValue(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewBufferString(`{
		"tenant_id":"t_acme",
		"agent_id":"agent_pr_reviewer",
		"run_id":"run_7f9",
		"tool_context":["github"],
		"attestation":{"kind":"k8s_sa_jwt","token":"jwt"}
	}{"extra":true}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(&stubService{}).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if !strings.Contains(recorder.Body.String(), "single JSON object") {
		t.Fatalf("body = %q, want single-object error", recorder.Body.String())
	}
}

func TestServer_RateLimitReturnsTooManyRequests(t *testing.T) {
	t.Parallel()

	limiter := ratelimit.New(ratelimit.Config{
		RequestsPerSecond: 1,
		Burst:             1,
		CleanupInterval:   time.Hour,
		MaxAge:            time.Hour,
		ExemptPaths:       map[string]bool{},
	})
	defer limiter.Close()

	server := httpapi.NewServer(&stubService{}, httpapi.WithRateLimiter(limiter))

	first := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewBufferString(`{}`))
	first.Header.Set("Content-Type", "application/json")
	first.RemoteAddr = "203.0.113.10:1234"
	firstRecorder := httptest.NewRecorder()
	server.ServeHTTP(firstRecorder, first)

	second := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewBufferString(`{}`))
	second.Header.Set("Content-Type", "application/json")
	second.RemoteAddr = "203.0.113.10:5678"
	secondRecorder := httptest.NewRecorder()
	server.ServeHTTP(secondRecorder, second)

	if secondRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", secondRecorder.Code, http.StatusTooManyRequests)
	}
	if got := secondRecorder.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("retry-after = %q, want %q", got, "1")
	}
}

func TestServer_ApproveGrant(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		approveGrant: func(_ context.Context, req *core.ApproveGrantRequest) (*core.RequestGrantResponse, error) {
			if req.ApprovalID != "ap_999" || req.Approver != "user:jonathan" {
				t.Fatalf("unexpected approve request: %#v", req)
			}
			return &core.RequestGrantResponse{
				GrantID: "gr_124",
				State:   core.GrantStateIssued,
				Delivery: &core.Delivery{
					Kind:       core.DeliveryKindWrappedSecret,
					ArtifactID: "art_1",
				},
				ExpiresAt: time.Date(2026, 3, 12, 20, 5, 0, 0, time.UTC),
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/ap_999:approve", bytes.NewBufferString(`{
		"approver":"user:jonathan",
		"comment":"expected browser login"
	}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(svc).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestServer_ExecuteGitHubProxy(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		executeGitHubProxy: func(_ context.Context, req *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error) {
			if req.ProxyHandle != "ph_456" || req.Operation != "pull_request_files" {
				t.Fatalf("unexpected proxy request: %#v", req)
			}
			return &core.ExecuteGitHubProxyResponse{
				Payload:     []byte(`{"files":[{"filename":"main.go"}]}`),
				ContentType: "application/json",
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/github/rest", bytes.NewBufferString(`{
		"proxy_handle":"ph_456",
		"operation":"pull_request_files",
		"params":{"owner":"acme","repo":"widgets","pull_number":142}
	}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(svc).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if recorder.Body.String() != `{"files":[{"filename":"main.go"}]}` {
		t.Fatalf("body = %s, want proxy payload", recorder.Body.String())
	}
}

func TestServer_RegisterBrowserRelayAndUnwrap(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		registerBrowserRelay: func(_ context.Context, req *core.RegisterBrowserRelayRequest) (*core.RegisterBrowserRelayResponse, error) {
			if req.KeyID != "key_1" || req.Origin != "https://admin.vendor.example" {
				t.Fatalf("unexpected register relay request: %#v", req)
			}
			return &core.RegisterBrowserRelayResponse{
				SessionID: "sess_abc",
				KeyID:     "key_1",
				ExpiresAt: time.Date(2026, 3, 12, 20, 15, 0, 0, time.UTC),
			}, nil
		},
		unwrapArtifact: func(_ context.Context, req *core.UnwrapArtifactRequest) (*core.UnwrapArtifactResponse, error) {
			if req.ArtifactID != "art_1" || req.KeyID != "key_1" {
				t.Fatalf("unexpected unwrap request: %#v", req)
			}
			return &core.UnwrapArtifactResponse{
				ArtifactID: "art_1",
				Origin:     "https://admin.vendor.example",
				Fields: []core.BrowserFillField{
					{Name: "username", Selector: "#username", Value: "admin"},
				},
			}, nil
		},
	}

	registerReq := httptest.NewRequest(http.MethodPost, "/v1/browser/relay-sessions", bytes.NewBufferString(`{
		"session_token":"eyJ.test",
		"key_id":"key_1",
		"public_key":"pubkey",
		"origin":"https://admin.vendor.example",
		"tab_id":"tab_42",
		"selectors":{"username":"#username","password":"#password"}
	}`))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRecorder := httptest.NewRecorder()

	httpapi.NewServer(svc).ServeHTTP(registerRecorder, registerReq)

	if registerRecorder.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerRecorder.Code, http.StatusOK)
	}

	unwrapReq := httptest.NewRequest(http.MethodPost, "/v1/artifacts/art_1:unwrap", bytes.NewBufferString(`{
		"session_token":"eyJ.test",
		"key_id":"key_1",
		"origin":"https://admin.vendor.example",
		"tab_id":"tab_42"
	}`))
	unwrapReq.Header.Set("Content-Type", "application/json")
	unwrapRecorder := httptest.NewRecorder()

	httpapi.NewServer(svc).ServeHTTP(unwrapRecorder, unwrapReq)

	if unwrapRecorder.Code != http.StatusOK {
		t.Fatalf("unwrap status = %d, want %d", unwrapRecorder.Code, http.StatusOK)
	}
}

func TestServer_ExecuteGitHubProxyRateLimited(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		executeGitHubProxy: func(context.Context, *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error) {
			return nil, core.ErrRateLimited
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/github/rest", bytes.NewBufferString(`{
		"proxy_handle":"ph_456",
		"operation":"repository_metadata",
		"params":{}
	}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	httpapi.NewServer(svc).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
}

type stubService struct {
	createSession        func(context.Context, *core.CreateSessionRequest) (*core.CreateSessionResponse, error)
	requestGrant         func(context.Context, *core.RequestGrantRequest) (*core.RequestGrantResponse, error)
	approveGrant         func(context.Context, *core.ApproveGrantRequest) (*core.RequestGrantResponse, error)
	denyGrant            func(context.Context, *core.DenyGrantRequest) error
	revokeGrant          func(context.Context, *core.RevokeGrantRequest) error
	revokeSession        func(context.Context, *core.RevokeSessionRequest) error
	executeGitHubProxy   func(context.Context, *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error)
	registerBrowserRelay func(context.Context, *core.RegisterBrowserRelayRequest) (*core.RegisterBrowserRelayResponse, error)
	unwrapArtifact       func(context.Context, *core.UnwrapArtifactRequest) (*core.UnwrapArtifactResponse, error)
}

func (s *stubService) CreateSession(ctx context.Context, req *core.CreateSessionRequest) (*core.CreateSessionResponse, error) {
	if s.createSession == nil {
		return nil, errors.New("unexpected create session call")
	}
	return s.createSession(ctx, req)
}

func (s *stubService) RequestGrant(ctx context.Context, req *core.RequestGrantRequest) (*core.RequestGrantResponse, error) {
	if s.requestGrant == nil {
		return nil, errors.New("unexpected request grant call")
	}
	return s.requestGrant(ctx, req)
}

func (s *stubService) ApproveGrant(ctx context.Context, req *core.ApproveGrantRequest) (*core.RequestGrantResponse, error) {
	if s.approveGrant == nil {
		return nil, errors.New("unexpected approve grant call")
	}
	return s.approveGrant(ctx, req)
}

func (s *stubService) DenyGrant(ctx context.Context, req *core.DenyGrantRequest) error {
	if s.denyGrant == nil {
		return errors.New("unexpected deny grant call")
	}
	return s.denyGrant(ctx, req)
}

func (s *stubService) RevokeGrant(ctx context.Context, req *core.RevokeGrantRequest) error {
	if s.revokeGrant == nil {
		return errors.New("unexpected revoke grant call")
	}
	return s.revokeGrant(ctx, req)
}

func (s *stubService) RevokeSession(ctx context.Context, req *core.RevokeSessionRequest) error {
	if s.revokeSession == nil {
		return errors.New("unexpected revoke session call")
	}
	return s.revokeSession(ctx, req)
}

func (s *stubService) ExecuteGitHubProxy(ctx context.Context, req *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error) {
	if s.executeGitHubProxy == nil {
		return nil, errors.New("unexpected execute github proxy call")
	}
	return s.executeGitHubProxy(ctx, req)
}

func (s *stubService) RegisterBrowserRelay(ctx context.Context, req *core.RegisterBrowserRelayRequest) (*core.RegisterBrowserRelayResponse, error) {
	if s.registerBrowserRelay == nil {
		return nil, errors.New("unexpected register browser relay call")
	}
	return s.registerBrowserRelay(ctx, req)
}

func (s *stubService) UnwrapArtifact(ctx context.Context, req *core.UnwrapArtifactRequest) (*core.UnwrapArtifactResponse, error) {
	if s.unwrapArtifact == nil {
		return nil, errors.New("unexpected unwrap artifact call")
	}
	return s.unwrapArtifact(ctx, req)
}
