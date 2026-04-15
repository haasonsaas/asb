package connectapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	connect "connectrpc.com/connect"
	"github.com/evalops/asb/internal/core"
	asbv1 "github.com/evalops/asb/proto/asb/v1"
	"github.com/evalops/asb/proto/asb/v1/asbv1connect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func NewHandler(service Service, options ...connect.HandlerOption) (string, http.Handler) {
	return asbv1connect.NewBrokerServiceHandler(&server{service: service}, options...)
}

type server struct {
	service Service
}

func (s *server) CreateSession(ctx context.Context, req *connect.Request[asbv1.CreateSessionRequest]) (*connect.Response[asbv1.CreateSessionResponse], error) {
	resp, err := s.service.CreateSession(ctx, &core.CreateSessionRequest{
		TenantID:    req.Msg.GetTenantId(),
		AgentID:     req.Msg.GetAgentId(),
		RunID:       req.Msg.GetRunId(),
		ToolContext: req.Msg.GetToolContext(),
		Attestation: &core.Attestation{
			Kind:  core.AttestationKind(req.Msg.GetAttestation().GetKind()),
			Token: req.Msg.GetAttestation().GetToken(),
		},
		DelegationAssertion: req.Msg.GetDelegationAssertion(),
	})
	if err != nil {
		return nil, connectError(err)
	}
	return connect.NewResponse(&asbv1.CreateSessionResponse{
		SessionId:    resp.SessionID,
		SessionToken: resp.SessionToken,
		ExpiresAt:    timestamppb.New(resp.ExpiresAt),
	}), nil
}

func (s *server) RequestGrant(ctx context.Context, req *connect.Request[asbv1.RequestGrantRequest]) (*connect.Response[asbv1.RequestGrantResponse], error) {
	resp, err := s.service.RequestGrant(ctx, &core.RequestGrantRequest{
		SessionToken: req.Msg.GetSessionToken(),
		Tool:         req.Msg.GetTool(),
		Capability:   req.Msg.GetCapability(),
		ResourceRef:  req.Msg.GetResourceRef(),
		DeliveryMode: core.DeliveryMode(req.Msg.GetDeliveryMode()),
		TTL:          time.Duration(req.Msg.GetTtlSeconds()) * time.Second,
		Reason:       req.Msg.GetReason(),
	})
	if err != nil {
		return nil, connectError(err)
	}
	return connect.NewResponse(toProtoGrantResponse(resp)), nil
}

func (s *server) ApproveGrant(ctx context.Context, req *connect.Request[asbv1.ApproveGrantRequest]) (*connect.Response[asbv1.ApproveGrantResponse], error) {
	resp, err := s.service.ApproveGrant(ctx, &core.ApproveGrantRequest{
		ApprovalID: req.Msg.GetApprovalId(),
		Approver:   req.Msg.GetApprover(),
		Comment:    req.Msg.GetComment(),
	})
	if err != nil {
		return nil, connectError(err)
	}
	return connect.NewResponse(toProtoApproveGrantResponse(resp)), nil
}

func (s *server) DenyGrant(ctx context.Context, req *connect.Request[asbv1.DenyGrantRequest]) (*connect.Response[asbv1.DenyGrantResponse], error) {
	if err := s.service.DenyGrant(ctx, &core.DenyGrantRequest{
		ApprovalID: req.Msg.GetApprovalId(),
		Approver:   req.Msg.GetApprover(),
		Comment:    req.Msg.GetComment(),
	}); err != nil {
		return nil, connectError(err)
	}
	return connect.NewResponse(&asbv1.DenyGrantResponse{State: "denied"}), nil
}

func (s *server) RevokeGrant(ctx context.Context, req *connect.Request[asbv1.RevokeGrantRequest]) (*connect.Response[asbv1.RevokeGrantResponse], error) {
	if err := s.service.RevokeGrant(ctx, &core.RevokeGrantRequest{
		GrantID: req.Msg.GetGrantId(),
		Reason:  req.Msg.GetReason(),
	}); err != nil {
		return nil, connectError(err)
	}
	return connect.NewResponse(&asbv1.RevokeGrantResponse{State: "revoked"}), nil
}

func (s *server) RevokeSession(ctx context.Context, req *connect.Request[asbv1.RevokeSessionRequest]) (*connect.Response[asbv1.RevokeSessionResponse], error) {
	if err := s.service.RevokeSession(ctx, &core.RevokeSessionRequest{
		SessionID: req.Msg.GetSessionId(),
		Reason:    req.Msg.GetReason(),
	}); err != nil {
		return nil, connectError(err)
	}
	return connect.NewResponse(&asbv1.RevokeSessionResponse{State: "revoked"}), nil
}

func (s *server) ExecuteGitHubProxy(ctx context.Context, req *connect.Request[asbv1.ExecuteGitHubProxyRequest]) (*connect.Response[asbv1.ExecuteGitHubProxyResponse], error) {
	params := map[string]any{}
	if req.Msg.GetParams() != nil {
		params = req.Msg.GetParams().AsMap()
	}
	resp, err := s.service.ExecuteGitHubProxy(ctx, &core.ExecuteGitHubProxyRequest{
		ProxyHandle: req.Msg.GetProxyHandle(),
		Operation:   req.Msg.GetOperation(),
		Params:      params,
	})
	if err != nil {
		return nil, connectError(err)
	}
	return connect.NewResponse(&asbv1.ExecuteGitHubProxyResponse{
		Payload:     resp.Payload,
		ContentType: resp.ContentType,
	}), nil
}

func (s *server) RegisterBrowserRelay(ctx context.Context, req *connect.Request[asbv1.RegisterBrowserRelayRequest]) (*connect.Response[asbv1.RegisterBrowserRelayResponse], error) {
	resp, err := s.service.RegisterBrowserRelay(ctx, &core.RegisterBrowserRelayRequest{
		SessionToken: req.Msg.GetSessionToken(),
		KeyID:        req.Msg.GetKeyId(),
		PublicKey:    req.Msg.GetPublicKey(),
		Origin:       req.Msg.GetOrigin(),
		TabID:        req.Msg.GetTabId(),
		Selectors:    req.Msg.GetSelectors(),
	})
	if err != nil {
		return nil, connectError(err)
	}
	return connect.NewResponse(&asbv1.RegisterBrowserRelayResponse{
		SessionId: resp.SessionID,
		KeyId:     resp.KeyID,
		ExpiresAt: timestamppb.New(resp.ExpiresAt),
	}), nil
}

func (s *server) UnwrapArtifact(ctx context.Context, req *connect.Request[asbv1.UnwrapArtifactRequest]) (*connect.Response[asbv1.UnwrapArtifactResponse], error) {
	resp, err := s.service.UnwrapArtifact(ctx, &core.UnwrapArtifactRequest{
		SessionToken: req.Msg.GetSessionToken(),
		ArtifactID:   req.Msg.GetArtifactId(),
		KeyID:        req.Msg.GetKeyId(),
		Origin:       req.Msg.GetOrigin(),
		TabID:        req.Msg.GetTabId(),
	})
	if err != nil {
		return nil, connectError(err)
	}
	fields := make([]*asbv1.BrowserFillField, 0, len(resp.Fields))
	for _, field := range resp.Fields {
		fields = append(fields, &asbv1.BrowserFillField{
			Name:     field.Name,
			Selector: field.Selector,
			Value:    field.Value,
		})
	}
	return connect.NewResponse(&asbv1.UnwrapArtifactResponse{
		ArtifactId: resp.ArtifactID,
		Origin:     resp.Origin,
		AutoSubmit: resp.AutoSubmit,
		Fields:     fields,
	}), nil
}

func toProtoDelivery(d *core.Delivery) *asbv1.Delivery {
	if d == nil {
		return nil
	}
	return &asbv1.Delivery{
		Kind:       string(d.Kind),
		Handle:     d.Handle,
		Token:      d.Token,
		ArtifactId: d.ArtifactID,
	}
}

func toProtoGrantResponse(resp *core.RequestGrantResponse) *asbv1.RequestGrantResponse {
	return &asbv1.RequestGrantResponse{
		GrantId:    resp.GrantID,
		State:      string(resp.State),
		ApprovalId: resp.ApprovalID,
		Delivery:   toProtoDelivery(resp.Delivery),
		ExpiresAt:  timestamppb.New(resp.ExpiresAt),
	}
}

func toProtoApproveGrantResponse(resp *core.RequestGrantResponse) *asbv1.ApproveGrantResponse {
	return &asbv1.ApproveGrantResponse{
		GrantId:    resp.GrantID,
		State:      string(resp.State),
		ApprovalId: resp.ApprovalID,
		Delivery:   toProtoDelivery(resp.Delivery),
		ExpiresAt:  timestamppb.New(resp.ExpiresAt),
	}
}

func connectError(err error) error {
	code := connect.CodeInternal
	switch {
	case errors.Is(err, core.ErrInvalidRequest):
		code = connect.CodeInvalidArgument
	case errors.Is(err, core.ErrDeliveryModeNotImplemented):
		code = connect.CodeUnimplemented
	case errors.Is(err, core.ErrUnauthorized):
		code = connect.CodeUnauthenticated
	case errors.Is(err, core.ErrForbidden):
		code = connect.CodePermissionDenied
	case errors.Is(err, core.ErrNotFound):
		code = connect.CodeNotFound
	case errors.Is(err, core.ErrResourceBudgetExceeded):
		code = connect.CodeResourceExhausted
	}
	return connect.NewError(code, err)
}

func structFromMap(values map[string]any) (*structpb.Struct, error) {
	if values == nil {
		return nil, nil
	}
	return structpb.NewStruct(values)
}
