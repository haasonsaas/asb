package connectapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	"github.com/evalops/asb/internal/api/connectapi"
	"github.com/evalops/asb/internal/core"
	asbv1 "github.com/evalops/asb/proto/asb/v1"
	"github.com/evalops/asb/proto/asb/v1/asbv1connect"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestServer_CreateSessionAndExecuteProxy(t *testing.T) {
	t.Parallel()

	svc := &stubService{
		createSession: func(_ context.Context, req *core.CreateSessionRequest) (*core.CreateSessionResponse, error) {
			if req.TenantID != "t_acme" {
				t.Fatalf("unexpected create request: %#v", req)
			}
			return &core.CreateSessionResponse{
				SessionID:    "sess_abc",
				SessionToken: "eyJ.test",
				ExpiresAt:    time.Date(2026, 3, 12, 20, 15, 0, 0, time.UTC),
			}, nil
		},
		executeGitHubProxy: func(_ context.Context, req *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error) {
			if req.ProxyHandle != "ph_456" {
				t.Fatalf("unexpected proxy request: %#v", req)
			}
			return &core.ExecuteGitHubProxyResponse{
				Payload:     []byte(`{"ok":true}`),
				ContentType: "application/json",
			}, nil
		},
	}

	path, handler := connectapi.NewHandler(svc)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := asbv1connect.NewBrokerServiceClient(server.Client(), server.URL)

	createResp, err := client.CreateSession(context.Background(), connect.NewRequest(&asbv1.CreateSessionRequest{
		TenantId:    "t_acme",
		AgentId:     "agent_pr_reviewer",
		RunId:       "run_7f9",
		ToolContext: []string{"github"},
		Attestation: &asbv1.Attestation{Kind: "k8s_sa_jwt", Token: "jwt"},
	}))
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if createResp.Msg.GetSessionId() != "sess_abc" {
		t.Fatalf("session_id = %q, want sess_abc", createResp.Msg.GetSessionId())
	}

	params, err := structpb.NewStruct(map[string]any{"pull_number": 142})
	if err != nil {
		t.Fatalf("NewStruct() error = %v", err)
	}
	proxyResp, err := client.ExecuteGitHubProxy(context.Background(), connect.NewRequest(&asbv1.ExecuteGitHubProxyRequest{
		ProxyHandle: "ph_456",
		Operation:   "pull_request_files",
		Params:      params,
	}))
	if err != nil {
		t.Fatalf("ExecuteGitHubProxy() error = %v", err)
	}
	if string(proxyResp.Msg.GetPayload()) != `{"ok":true}` {
		t.Fatalf("payload = %s, want expected proxy payload", string(proxyResp.Msg.GetPayload()))
	}
}

func TestServer_MapsCoreErrorsToConnectCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want connect.Code
	}{
		{name: "invalid request", err: core.ErrInvalidRequest, want: connect.CodeInvalidArgument},
		{name: "unimplemented delivery mode", err: core.ErrDeliveryModeNotImplemented, want: connect.CodeUnimplemented},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := &stubService{
				createSession: func(context.Context, *core.CreateSessionRequest) (*core.CreateSessionResponse, error) {
					return nil, tt.err
				},
			}

			path, handler := connectapi.NewHandler(svc)
			mux := http.NewServeMux()
			mux.Handle(path, handler)
			server := httptest.NewServer(mux)
			defer server.Close()

			client := asbv1connect.NewBrokerServiceClient(server.Client(), server.URL)
			_, err := client.CreateSession(context.Background(), connect.NewRequest(&asbv1.CreateSessionRequest{}))
			if err == nil {
				t.Fatal("CreateSession() error = nil, want non-nil")
			}
			var connectErr *connect.Error
			if !errors.As(err, &connectErr) {
				t.Fatalf("error = %T, want *connect.Error", err)
			}
			if connectErr.Code() != tt.want {
				t.Fatalf("code = %v, want %v", connectErr.Code(), tt.want)
			}
		})
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
	return s.createSession(ctx, req)
}

func (s *stubService) RequestGrant(ctx context.Context, req *core.RequestGrantRequest) (*core.RequestGrantResponse, error) {
	return s.requestGrant(ctx, req)
}

func (s *stubService) ApproveGrant(ctx context.Context, req *core.ApproveGrantRequest) (*core.RequestGrantResponse, error) {
	return s.approveGrant(ctx, req)
}

func (s *stubService) DenyGrant(ctx context.Context, req *core.DenyGrantRequest) error {
	return s.denyGrant(ctx, req)
}

func (s *stubService) RevokeGrant(ctx context.Context, req *core.RevokeGrantRequest) error {
	return s.revokeGrant(ctx, req)
}

func (s *stubService) RevokeSession(ctx context.Context, req *core.RevokeSessionRequest) error {
	return s.revokeSession(ctx, req)
}

func (s *stubService) ExecuteGitHubProxy(ctx context.Context, req *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error) {
	return s.executeGitHubProxy(ctx, req)
}

func (s *stubService) RegisterBrowserRelay(ctx context.Context, req *core.RegisterBrowserRelayRequest) (*core.RegisterBrowserRelayResponse, error) {
	return s.registerBrowserRelay(ctx, req)
}

func (s *stubService) UnwrapArtifact(ctx context.Context, req *core.UnwrapArtifactRequest) (*core.UnwrapArtifactResponse, error) {
	return s.unwrapArtifact(ctx, req)
}
