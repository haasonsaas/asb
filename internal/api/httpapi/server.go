package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/evalops/asb/internal/core"
)

type Service interface {
	CreateSession(ctx context.Context, req *core.CreateSessionRequest) (*core.CreateSessionResponse, error)
	RequestGrant(ctx context.Context, req *core.RequestGrantRequest) (*core.RequestGrantResponse, error)
	ApproveGrant(ctx context.Context, req *core.ApproveGrantRequest) (*core.RequestGrantResponse, error)
	DenyGrant(ctx context.Context, req *core.DenyGrantRequest) error
	RevokeGrant(ctx context.Context, req *core.RevokeGrantRequest) error
	RevokeSession(ctx context.Context, req *core.RevokeSessionRequest) error
	ExecuteGitHubProxy(ctx context.Context, req *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error)
	RegisterBrowserRelay(ctx context.Context, req *core.RegisterBrowserRelayRequest) (*core.RegisterBrowserRelayResponse, error)
	UnwrapArtifact(ctx context.Context, req *core.UnwrapArtifactRequest) (*core.UnwrapArtifactResponse, error)
}

type Server struct {
	service  Service
	maxBody  int64
	timeouts requestTimeouts
}

type Option func(*Server)

type requestTimeouts struct {
	defaultTimeout time.Duration
	grantTimeout   time.Duration
	proxyTimeout   time.Duration
}

const (
	defaultMaxBodyBytes   int64         = 1 << 20
	defaultRequestTimeout time.Duration = 10 * time.Second
	defaultGrantTimeout   time.Duration = 20 * time.Second
	defaultProxyTimeout   time.Duration = 30 * time.Second
)

var errUnsupportedContentType = errors.New("content-type must be application/json")

func NewServer(service Service, options ...Option) *Server {
	server := &Server{
		service: service,
		maxBody: defaultMaxBodyBytes,
		timeouts: requestTimeouts{
			defaultTimeout: defaultRequestTimeout,
			grantTimeout:   defaultGrantTimeout,
			proxyTimeout:   defaultProxyTimeout,
		},
	}
	for _, option := range options {
		option(server)
	}
	return server
}

func WithMaxBodyBytes(limit int64) Option {
	return func(server *Server) {
		if limit > 0 {
			server.maxBody = limit
		}
	}
}

func WithRequestTimeouts(defaultTimeout time.Duration, grantTimeout time.Duration, proxyTimeout time.Duration) Option {
	return func(server *Server) {
		if defaultTimeout > 0 {
			server.timeouts.defaultTimeout = defaultTimeout
		}
		if grantTimeout > 0 {
			server.timeouts.grantTimeout = grantTimeout
		}
		if proxyTimeout > 0 {
			server.timeouts.proxyTimeout = proxyTimeout
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sessions":
		s.handleCreateSession(w, s.withTimeout(r, s.timeouts.defaultTimeout))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/grants":
		s.handleRequestGrant(w, s.withTimeout(r, s.timeouts.grantTimeout))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/approvals/") && strings.HasSuffix(r.URL.Path, ":approve"):
		s.handleApproveGrant(w, s.withTimeout(r, s.timeouts.grantTimeout))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/approvals/") && strings.HasSuffix(r.URL.Path, ":deny"):
		s.handleDenyGrant(w, s.withTimeout(r, s.timeouts.defaultTimeout))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/grants/") && strings.HasSuffix(r.URL.Path, ":revoke"):
		s.handleRevokeGrant(w, s.withTimeout(r, s.timeouts.defaultTimeout))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/sessions/") && strings.HasSuffix(r.URL.Path, ":revoke"):
		s.handleRevokeSession(w, s.withTimeout(r, s.timeouts.defaultTimeout))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/proxy/github/rest":
		s.handleExecuteGitHubProxy(w, s.withTimeout(r, s.timeouts.proxyTimeout))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/browser/relay-sessions":
		s.handleRegisterBrowserRelay(w, s.withTimeout(r, s.timeouts.defaultTimeout))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/artifacts/") && strings.HasSuffix(r.URL.Path, ":unwrap"):
		s.handleUnwrapArtifact(w, s.withTimeout(r, s.timeouts.defaultTimeout))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := s.service.CreateSession(r.Context(), &core.CreateSessionRequest{
		TenantID:    req.TenantID,
		AgentID:     req.AgentID,
		RunID:       req.RunID,
		ToolContext: req.ToolContext,
		Attestation: &core.Attestation{
			Kind:  core.AttestationKind(req.Attestation.Kind),
			Token: req.Attestation.Token,
		},
		DelegationAssertion: req.DelegationAssertion,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":    resp.SessionID,
		"session_token": resp.SessionToken,
		"expires_at":    resp.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleRequestGrant(w http.ResponseWriter, r *http.Request) {
	var req requestGrantRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := s.service.RequestGrant(r.Context(), &core.RequestGrantRequest{
		SessionToken: req.SessionToken,
		Tool:         req.Tool,
		Capability:   req.Capability,
		ResourceRef:  req.ResourceRef,
		DeliveryMode: core.DeliveryMode(req.DeliveryMode),
		TTL:          time.Duration(req.TTLSeconds) * time.Second,
		Reason:       req.Reason,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	writeGrantResponse(w, resp)
}

func (s *Server) handleApproveGrant(w http.ResponseWriter, r *http.Request) {
	var req approvalDecisionRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}

	approvalID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/approvals/"), ":approve")
	resp, err := s.service.ApproveGrant(r.Context(), &core.ApproveGrantRequest{
		ApprovalID: approvalID,
		Approver:   req.Approver,
		Comment:    req.Comment,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	writeGrantResponse(w, resp)
}

func (s *Server) handleDenyGrant(w http.ResponseWriter, r *http.Request) {
	var req approvalDecisionRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}

	approvalID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/approvals/"), ":deny")
	err := s.service.DenyGrant(r.Context(), &core.DenyGrantRequest{
		ApprovalID: approvalID,
		Approver:   req.Approver,
		Comment:    req.Comment,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "denied"})
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := s.decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, err)
		return
	}

	grantID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/grants/"), ":revoke")
	if err := s.service.RevokeGrant(r.Context(), &core.RevokeGrantRequest{
		GrantID: grantID,
		Reason:  req.Reason,
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "revoked"})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := s.decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, err)
		return
	}

	sessionID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/sessions/"), ":revoke")
	if err := s.service.RevokeSession(r.Context(), &core.RevokeSessionRequest{
		SessionID: sessionID,
		Reason:    req.Reason,
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "revoked"})
}

func (s *Server) handleExecuteGitHubProxy(w http.ResponseWriter, r *http.Request) {
	var req executeGitHubProxyRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := s.service.ExecuteGitHubProxy(r.Context(), &core.ExecuteGitHubProxyRequest{
		ProxyHandle: req.ProxyHandle,
		Operation:   req.Operation,
		Params:      req.Params,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", resp.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp.Payload)
}

func (s *Server) handleRegisterBrowserRelay(w http.ResponseWriter, r *http.Request) {
	var req registerBrowserRelayRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := s.service.RegisterBrowserRelay(r.Context(), &core.RegisterBrowserRelayRequest{
		SessionToken: req.SessionToken,
		KeyID:        req.KeyID,
		PublicKey:    req.PublicKey,
		Origin:       req.Origin,
		TabID:        req.TabID,
		Selectors:    req.Selectors,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": resp.SessionID,
		"key_id":     resp.KeyID,
		"expires_at": resp.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleUnwrapArtifact(w http.ResponseWriter, r *http.Request) {
	var req unwrapArtifactRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	artifactID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/artifacts/"), ":unwrap")
	resp, err := s.service.UnwrapArtifact(r.Context(), &core.UnwrapArtifactRequest{
		SessionToken: req.SessionToken,
		ArtifactID:   artifactID,
		KeyID:        req.KeyID,
		Origin:       req.Origin,
		TabID:        req.TabID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"artifact_id": resp.ArtifactID,
		"origin":      resp.Origin,
		"auto_submit": resp.AutoSubmit,
		"fields":      resp.Fields,
	})
}

func writeGrantResponse(w http.ResponseWriter, resp *core.RequestGrantResponse) {
	payload := map[string]any{
		"grant_id":    resp.GrantID,
		"state":       string(resp.State),
		"approval_id": resp.ApprovalID,
		"expires_at":  resp.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if resp.Delivery != nil {
		payload["delivery"] = map[string]any{
			"kind":        string(resp.Delivery.Kind),
			"handle":      resp.Delivery.Handle,
			"token":       resp.Delivery.Token,
			"artifact_id": resp.Delivery.ArtifactID,
		}
	}
	writeJSON(w, http.StatusOK, payload)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var maxBytesErr *http.MaxBytesError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	case errors.Is(err, errUnsupportedContentType):
		status = http.StatusUnsupportedMediaType
	case errors.As(err, &maxBytesErr):
		status = http.StatusRequestEntityTooLarge
	case errors.As(err, &syntaxErr), errors.As(err, &typeErr), errors.Is(err, io.EOF):
		status = http.StatusBadRequest
	case errors.Is(err, core.ErrInvalidRequest):
		status = http.StatusBadRequest
	case errors.Is(err, core.ErrUnauthorized):
		status = http.StatusUnauthorized
	case errors.Is(err, core.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, core.ErrNotFound):
		status = http.StatusNotFound
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) withTimeout(r *http.Request, timeout time.Duration) *http.Request {
	if timeout <= 0 {
		return r
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	return r.Clone(context.WithValue(ctx, requestCancelKey{}, cancel))
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, out any) error {
	defer s.finishRequest(r)

	if err := requireJSONContentType(r); err != nil {
		return err
	}

	body := http.MaxBytesReader(w, r.Body, s.maxBody)
	defer body.Close()

	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != nil && !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

type requestCancelKey struct{}

func (s *Server) finishRequest(r *http.Request) {
	cancel, _ := r.Context().Value(requestCancelKey{}).(context.CancelFunc)
	if cancel != nil {
		cancel()
	}
}

func requireJSONContentType(r *http.Request) error {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType == "" {
		return errUnsupportedContentType
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return errUnsupportedContentType
	}
	if mediaType != "application/json" {
		return errUnsupportedContentType
	}
	return nil
}

type createSessionRequest struct {
	TenantID            string   `json:"tenant_id"`
	AgentID             string   `json:"agent_id"`
	RunID               string   `json:"run_id"`
	ToolContext         []string `json:"tool_context"`
	DelegationAssertion string   `json:"delegation_assertion"`
	Attestation         struct {
		Kind  string `json:"kind"`
		Token string `json:"token"`
	} `json:"attestation"`
}

type requestGrantRequest struct {
	SessionToken string `json:"session_token"`
	Tool         string `json:"tool"`
	Capability   string `json:"capability"`
	ResourceRef  string `json:"resource_ref"`
	DeliveryMode string `json:"delivery_mode"`
	TTLSeconds   int    `json:"ttl_seconds"`
	Reason       string `json:"reason"`
}

type approvalDecisionRequest struct {
	Approver string `json:"approver"`
	Comment  string `json:"comment"`
}

type revokeRequest struct {
	Reason string `json:"reason"`
}

type executeGitHubProxyRequest struct {
	ProxyHandle string         `json:"proxy_handle"`
	Operation   string         `json:"operation"`
	Params      map[string]any `json:"params"`
}

type registerBrowserRelayRequest struct {
	SessionToken string            `json:"session_token"`
	KeyID        string            `json:"key_id"`
	PublicKey    string            `json:"public_key"`
	Origin       string            `json:"origin"`
	TabID        string            `json:"tab_id"`
	Selectors    map[string]string `json:"selectors"`
}

type unwrapArtifactRequest struct {
	SessionToken string `json:"session_token"`
	KeyID        string `json:"key_id"`
	Origin       string `json:"origin"`
	TabID        string `json:"tab_id"`
}
