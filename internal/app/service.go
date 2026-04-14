package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/asb/internal/core"
)

const (
	sessionTTL  = 15 * time.Minute
	approvalTTL = 5 * time.Minute
)

type Config struct {
	Logger              *slog.Logger
	Clock               core.Clock
	IDs                 core.IDGenerator
	Metrics             *Metrics
	Repository          core.Repository
	Verifier            core.AttestationVerifier
	DelegationValidator core.DelegationValidator
	SessionTokens       core.SessionTokenManager
	Policy              core.PolicyEngine
	Tools               core.ToolRegistry
	Connectors          core.ConnectorResolver
	Deliveries          map[core.DeliveryMode]core.DeliveryAdapter
	ApprovalNotifier    core.ApprovalNotifier
	Audit               core.AuditSink
	Runtime             core.RuntimeStore
	GitHubProxy         core.GitHubProxyExecutor
}

type Service struct {
	logger              *slog.Logger
	clock               core.Clock
	ids                 core.IDGenerator
	metrics             *Metrics
	repo                core.Repository
	verifier            core.AttestationVerifier
	delegationValidator core.DelegationValidator
	sessionTokens       core.SessionTokenManager
	policy              core.PolicyEngine
	tools               core.ToolRegistry
	connectors          core.ConnectorResolver
	deliveries          map[core.DeliveryMode]core.DeliveryAdapter
	approvalNotifier    core.ApprovalNotifier
	audit               core.AuditSink
	runtime             core.RuntimeStore
	githubProxy         core.GitHubProxyExecutor
}

func NewService(cfg Config) (*Service, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.IDs == nil {
		cfg.IDs = timeIDs{}
	}
	if cfg.Repository == nil || cfg.Verifier == nil || cfg.SessionTokens == nil || cfg.Policy == nil || cfg.Tools == nil || cfg.Connectors == nil {
		return nil, fmt.Errorf("%w: repository, verifier, session tokens, policy, tools, and connectors are required", core.ErrInvalidRequest)
	}
	if cfg.Deliveries == nil {
		cfg.Deliveries = map[core.DeliveryMode]core.DeliveryAdapter{}
	}

	return &Service{
		logger:              cfg.Logger,
		clock:               cfg.Clock,
		ids:                 cfg.IDs,
		metrics:             cfg.Metrics,
		repo:                cfg.Repository,
		verifier:            cfg.Verifier,
		delegationValidator: cfg.DelegationValidator,
		sessionTokens:       cfg.SessionTokens,
		policy:              cfg.Policy,
		tools:               cfg.Tools,
		connectors:          cfg.Connectors,
		deliveries:          cfg.Deliveries,
		approvalNotifier:    cfg.ApprovalNotifier,
		audit:               cfg.Audit,
		runtime:             cfg.Runtime,
		githubProxy:         cfg.GitHubProxy,
	}, nil
}

func (s *Service) CreateSession(ctx context.Context, req *core.CreateSessionRequest) (*core.CreateSessionResponse, error) {
	if req == nil || req.TenantID == "" || req.AgentID == "" || req.RunID == "" || req.Attestation == nil {
		return nil, fmt.Errorf("%w: tenant_id, agent_id, run_id, and attestation are required", core.ErrInvalidRequest)
	}

	workload, err := s.verifier.Verify(ctx, req.Attestation)
	if err != nil {
		return nil, fmt.Errorf("create session for agent %q run %q: verify attestation: %w", req.AgentID, req.RunID, err)
	}

	var delegation *core.Delegation
	if req.DelegationAssertion != "" {
		if s.delegationValidator == nil {
			return nil, fmt.Errorf("%w: delegation validator is not configured", core.ErrInvalidRequest)
		}
		delegation, err = s.delegationValidator.Validate(ctx, req.DelegationAssertion, req.TenantID, req.AgentID)
		if err != nil {
			return nil, fmt.Errorf("create session for agent %q run %q: validate delegation: %w", req.AgentID, req.RunID, err)
		}
	}

	now := s.clock.Now()
	session := &core.Session{
		ID:               s.ids.New("sess"),
		TenantID:         req.TenantID,
		AgentID:          req.AgentID,
		RunID:            req.RunID,
		WorkloadIdentity: *workload,
		Delegation:       delegation,
		ToolContext:      append([]string(nil), req.ToolContext...),
		WorkloadHash:     hashWorkload(workload),
		ExpiresAt:        now.Add(sessionTTL),
		State:            core.SessionStateActive,
		CreatedAt:        now,
	}
	if err := s.repo.SaveSession(ctx, session); err != nil {
		return nil, fmt.Errorf("create session %q: save session: %w", session.ID, err)
	}
	s.metrics.recordSessionCreated(session.TenantID)

	if delegation != nil {
		s.appendAudit(ctx, &core.AuditEvent{
			EventID:   s.ids.New("evt"),
			TenantID:  req.TenantID,
			EventType: "delegation.validated",
			SessionID: session.ID,
			RunID:     session.RunID,
			Actor:     delegation.Subject,
			CreatedAt: now,
		})
	}
	s.appendAudit(ctx, &core.AuditEvent{
		EventID:   s.ids.New("evt"),
		TenantID:  req.TenantID,
		EventType: "session.created",
		SessionID: session.ID,
		RunID:     session.RunID,
		Actor:     req.AgentID,
		CreatedAt: now,
	})

	token, err := s.sessionTokens.Sign(session)
	if err != nil {
		return nil, fmt.Errorf("create session %q: sign session token: %w", session.ID, err)
	}

	return &core.CreateSessionResponse{
		SessionID:    session.ID,
		SessionToken: token,
		ExpiresAt:    session.ExpiresAt,
	}, nil
}

func (s *Service) RequestGrant(ctx context.Context, req *core.RequestGrantRequest) (*core.RequestGrantResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: request grant payload is required", core.ErrInvalidRequest)
	}
	session, claims, err := s.loadActiveSession(ctx, req.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("request grant for tool %q capability %q: load active session: %w", req.Tool, req.Capability, err)
	}

	resource, err := core.ParseResource(req.ResourceRef)
	if err != nil {
		return nil, fmt.Errorf("request grant for session %q: parse resource %q: %w", session.ID, req.ResourceRef, err)
	}

	if err := s.ensureDelegationAllows(session, req, resource); err != nil {
		return nil, fmt.Errorf("request grant for session %q: validate delegation for resource %q: %w", session.ID, req.ResourceRef, err)
	}

	tool, err := s.tools.Get(ctx, claims.TenantID, req.Tool)
	if err != nil {
		return nil, fmt.Errorf("request grant for session %q: load tool %q: %w", session.ID, req.Tool, err)
	}

	connector, err := s.connectors.Resolve(ctx, req.Capability, req.ResourceRef)
	if err != nil {
		return nil, fmt.Errorf("request grant for session %q: resolve connector for capability %q resource %q: %w", session.ID, req.Capability, req.ResourceRef, err)
	}
	if err := connector.ValidateResource(ctx, core.ValidateResourceRequest{
		TenantID:    session.TenantID,
		Capability:  req.Capability,
		ResourceRef: req.ResourceRef,
	}); err != nil {
		return nil, fmt.Errorf("request grant for session %q: validate resource %q: %w", session.ID, req.ResourceRef, err)
	}

	decision, err := s.policy.Evaluate(ctx, &core.DecisionInput{
		Session:  session,
		Request:  req,
		Tool:     tool,
		Resource: resource,
	})
	if err != nil {
		return nil, fmt.Errorf("request grant for session %q: evaluate policy for capability %q: %w", session.ID, req.Capability, err)
	}
	s.metrics.recordPolicyEvaluation(req.Capability, decision.Allowed)
	if !decision.Allowed {
		return nil, fmt.Errorf("%w: %s", core.ErrForbidden, decision.Reason)
	}

	now := s.clock.Now()
	grant := &core.Grant{
		ID:            s.ids.New("gr"),
		TenantID:      session.TenantID,
		SessionID:     session.ID,
		Capability:    req.Capability,
		ResourceRef:   req.ResourceRef,
		Tool:          req.Tool,
		DeliveryMode:  req.DeliveryMode,
		RequestedTTL:  req.TTL,
		EffectiveTTL:  decision.EffectiveTTL,
		ConnectorKind: connector.Kind(),
		Reason:        req.Reason,
		State:         core.GrantStatePending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(decision.EffectiveTTL),
	}

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:     s.ids.New("evt"),
		TenantID:    session.TenantID,
		EventType:   "grant.requested",
		SessionID:   session.ID,
		RunID:       session.RunID,
		GrantID:     grant.ID,
		Actor:       session.AgentID,
		Tool:        grant.Tool,
		Capability:  grant.Capability,
		ResourceRef: grant.ResourceRef,
		CreatedAt:   now,
	})

	if decision.ApprovalMode != core.ApprovalModeNone {
		approval := &core.Approval{
			ID:          s.ids.New("ap"),
			TenantID:    session.TenantID,
			GrantID:     grant.ID,
			RequestedBy: session.AgentID,
			Reason:      req.Reason,
			ExpiresAt:   now.Add(approvalTTL),
			State:       core.ApprovalStatePending,
			CreatedAt:   now,
		}
		grant.ApprovalID = &approval.ID
		if err := s.repo.SaveGrant(ctx, grant); err != nil {
			return nil, fmt.Errorf("request grant %q: save pending grant: %w", grant.ID, err)
		}
		if err := s.repo.SaveApproval(ctx, approval); err != nil {
			return nil, fmt.Errorf("request grant %q: save pending approval %q: %w", grant.ID, approval.ID, err)
		}
		s.metrics.recordGrantCreated(grant.State, grant.EffectiveTTL)
		s.appendAudit(ctx, &core.AuditEvent{
			EventID:     s.ids.New("evt"),
			TenantID:    session.TenantID,
			EventType:   "grant.pending_approval",
			SessionID:   session.ID,
			RunID:       session.RunID,
			GrantID:     grant.ID,
			Actor:       session.AgentID,
			Tool:        grant.Tool,
			Capability:  grant.Capability,
			ResourceRef: grant.ResourceRef,
			CreatedAt:   now,
		})
		if s.approvalNotifier != nil {
			if err := s.approvalNotifier.NotifyPending(ctx, nil, approval, grant); err != nil {
				return nil, fmt.Errorf("request grant %q: notify pending approval %q: %w", grant.ID, approval.ID, err)
			}
		}
		return &core.RequestGrantResponse{
			GrantID:    grant.ID,
			State:      grant.State,
			ApprovalID: approval.ID,
			ExpiresAt:  approval.ExpiresAt,
		}, nil
	}

	resp, err := s.issueGrant(ctx, session, grant, resource, connector)
	if err != nil {
		return nil, fmt.Errorf("request grant %q: issue grant: %w", grant.ID, err)
	}
	return resp, nil
}

func (s *Service) ApproveGrant(ctx context.Context, req *core.ApproveGrantRequest) (*core.RequestGrantResponse, error) {
	if req == nil || req.ApprovalID == "" || req.Approver == "" {
		return nil, fmt.Errorf("%w: approval_id and approver are required", core.ErrInvalidRequest)
	}

	approval, err := s.repo.GetApproval(ctx, req.ApprovalID)
	if err != nil {
		return nil, fmt.Errorf("approve grant via approval %q: load approval: %w", req.ApprovalID, err)
	}
	if approval.State != core.ApprovalStatePending {
		return nil, fmt.Errorf("%w: approval is not pending", core.ErrForbidden)
	}
	if s.clock.Now().After(approval.ExpiresAt) {
		approval.State = core.ApprovalStateExpired
		if err := s.repo.SaveApproval(ctx, approval); err != nil {
			return nil, fmt.Errorf("approve grant via approval %q: expire approval: %w", req.ApprovalID, err)
		}
		s.metrics.recordApprovalTransition(approval.State, s.clock.Now().Sub(approval.CreatedAt))
		return nil, fmt.Errorf("%w: approval expired", core.ErrForbidden)
	}

	grant, err := s.repo.GetGrant(ctx, approval.GrantID)
	if err != nil {
		return nil, fmt.Errorf("approve grant via approval %q: load grant %q: %w", req.ApprovalID, approval.GrantID, err)
	}
	session, err := s.repo.GetSession(ctx, grant.SessionID)
	if err != nil {
		return nil, fmt.Errorf("approve grant %q: load session %q: %w", grant.ID, grant.SessionID, err)
	}

	approver := req.Approver
	approval.ApprovedBy = &approver
	approval.Comment = req.Comment
	approval.State = core.ApprovalStateApproved
	if err := s.repo.SaveApproval(ctx, approval); err != nil {
		return nil, fmt.Errorf("approve grant %q: save approved approval %q: %w", grant.ID, approval.ID, err)
	}
	s.metrics.recordApprovalTransition(approval.State, s.clock.Now().Sub(approval.CreatedAt))

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:   s.ids.New("evt"),
		TenantID:  session.TenantID,
		EventType: "approval.approved",
		SessionID: session.ID,
		RunID:     session.RunID,
		GrantID:   grant.ID,
		Actor:     req.Approver,
		CreatedAt: s.clock.Now(),
	})

	resource, err := core.ParseResource(grant.ResourceRef)
	if err != nil {
		return nil, fmt.Errorf("approve grant %q: parse resource %q: %w", grant.ID, grant.ResourceRef, err)
	}
	connector, err := s.connectors.Resolve(ctx, grant.Capability, grant.ResourceRef)
	if err != nil {
		return nil, fmt.Errorf("approve grant %q: resolve connector: %w", grant.ID, err)
	}
	resp, err := s.issueGrant(ctx, session, grant, resource, connector)
	if err != nil {
		return nil, fmt.Errorf("approve grant %q: issue grant: %w", grant.ID, err)
	}
	return resp, nil
}

func (s *Service) DenyGrant(ctx context.Context, req *core.DenyGrantRequest) error {
	if req == nil || req.ApprovalID == "" || req.Approver == "" {
		return fmt.Errorf("%w: approval_id and approver are required", core.ErrInvalidRequest)
	}

	approval, err := s.repo.GetApproval(ctx, req.ApprovalID)
	if err != nil {
		return fmt.Errorf("deny grant via approval %q: load approval: %w", req.ApprovalID, err)
	}
	grant, err := s.repo.GetGrant(ctx, approval.GrantID)
	if err != nil {
		return fmt.Errorf("deny grant via approval %q: load grant %q: %w", req.ApprovalID, approval.GrantID, err)
	}

	approver := req.Approver
	approval.ApprovedBy = &approver
	approval.Comment = req.Comment
	approval.State = core.ApprovalStateDenied
	grant.State = core.GrantStateDenied
	if err := s.repo.SaveApproval(ctx, approval); err != nil {
		return fmt.Errorf("deny grant %q: save denied approval %q: %w", grant.ID, approval.ID, err)
	}
	if err := s.repo.SaveGrant(ctx, grant); err != nil {
		return fmt.Errorf("deny grant %q: save denied grant: %w", grant.ID, err)
	}
	s.metrics.recordApprovalTransition(approval.State, s.clock.Now().Sub(approval.CreatedAt))
	s.metrics.recordGrantTransition(grant.State)

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:   s.ids.New("evt"),
		TenantID:  grant.TenantID,
		EventType: "approval.denied",
		GrantID:   grant.ID,
		Actor:     req.Approver,
		CreatedAt: s.clock.Now(),
	})
	return nil
}

func (s *Service) RevokeGrant(ctx context.Context, req *core.RevokeGrantRequest) error {
	if req == nil || req.GrantID == "" {
		return fmt.Errorf("%w: grant_id is required", core.ErrInvalidRequest)
	}

	grant, err := s.repo.GetGrant(ctx, req.GrantID)
	if err != nil {
		return fmt.Errorf("revoke grant %q: load grant: %w", req.GrantID, err)
	}
	session, err := s.repo.GetSession(ctx, grant.SessionID)
	if err != nil {
		return fmt.Errorf("revoke grant %q: load session %q: %w", grant.ID, grant.SessionID, err)
	}
	if err := s.transitionGrantState(ctx, session, grant, core.GrantStateRevoked, req.Reason); err != nil {
		return fmt.Errorf("revoke grant %q: transition state: %w", grant.ID, err)
	}
	return nil
}

func (s *Service) RevokeSession(ctx context.Context, req *core.RevokeSessionRequest) error {
	if req == nil || req.SessionID == "" {
		return fmt.Errorf("%w: session_id is required", core.ErrInvalidRequest)
	}

	session, err := s.repo.GetSession(ctx, req.SessionID)
	if err != nil {
		return fmt.Errorf("revoke session %q: load session: %w", req.SessionID, err)
	}
	previousState := session.State
	session.State = core.SessionStateRevoked
	if err := s.repo.SaveSession(ctx, session); err != nil {
		return fmt.Errorf("revoke session %q: save session: %w", session.ID, err)
	}
	s.metrics.recordSessionTransition(previousState, session.State, session.TenantID)

	grants, err := s.repo.ListGrantsBySession(ctx, req.SessionID)
	if err != nil {
		return fmt.Errorf("revoke session %q: list grants: %w", session.ID, err)
	}
	for _, grant := range grants {
		if grant.State == core.GrantStateRevoked || grant.State == core.GrantStateDenied || grant.State == core.GrantStateExpired {
			continue
		}

		if err := s.transitionGrantState(ctx, session, grant, core.GrantStateRevoked, req.Reason); err != nil {
			return fmt.Errorf("revoke session %q: revoke grant %q: %w", session.ID, grant.ID, err)
		}
	}

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:   s.ids.New("evt"),
		TenantID:  session.TenantID,
		EventType: "session.revoked",
		SessionID: session.ID,
		RunID:     session.RunID,
		Actor:     session.AgentID,
		CreatedAt: s.clock.Now(),
	})
	return nil
}

func (s *Service) ExecuteGitHubProxy(ctx context.Context, req *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error) {
	if req == nil || req.ProxyHandle == "" || req.Operation == "" {
		return nil, fmt.Errorf("%w: proxy_handle and operation are required", core.ErrInvalidRequest)
	}
	if s.githubProxy == nil {
		return nil, fmt.Errorf("%w: github proxy executor is not configured", core.ErrInvalidRequest)
	}

	artifact, err := s.repo.GetArtifactByHandle(ctx, req.ProxyHandle)
	if err != nil {
		return nil, fmt.Errorf("execute github proxy %q: load artifact by handle: %w", req.ProxyHandle, err)
	}
	if artifact.Kind != core.ArtifactKindProxyHandle {
		return nil, fmt.Errorf("%w: artifact %q is not a proxy handle", core.ErrForbidden, artifact.ID)
	}
	if !artifact.ExpiresAt.IsZero() && s.clock.Now().After(artifact.ExpiresAt) {
		return nil, fmt.Errorf("%w: proxy handle expired", core.ErrForbidden)
	}
	if !operationAllowed(artifact.Metadata["operations"], req.Operation) {
		return nil, fmt.Errorf("%w: proxy operation %q is not allowlisted", core.ErrForbidden, req.Operation)
	}

	session, err := s.repo.GetSession(ctx, artifact.SessionID)
	if err != nil {
		return nil, fmt.Errorf("execute github proxy %q: load session %q: %w", req.ProxyHandle, artifact.SessionID, err)
	}
	if session.State != core.SessionStateActive {
		return nil, fmt.Errorf("%w: session is not active", core.ErrForbidden)
	}
	grant, err := s.repo.GetGrant(ctx, artifact.GrantID)
	if err != nil {
		return nil, fmt.Errorf("execute github proxy %q: load grant %q: %w", req.ProxyHandle, artifact.GrantID, err)
	}
	if grant.State != core.GrantStateIssued {
		return nil, fmt.Errorf("%w: grant is not issued", core.ErrForbidden)
	}

	acquired := false
	responseBytes := int64(0)
	if s.runtime != nil {
		if err := s.runtime.AcquireProxyRequest(ctx, req.ProxyHandle); err != nil {
			if errors.Is(err, core.ErrResourceBudgetExceeded) {
				s.metrics.recordBudgetExhaustion(req.ProxyHandle)
			}
			return nil, fmt.Errorf("execute github proxy %q: acquire proxy request budget: %w", req.ProxyHandle, err)
		}
		acquired = true
	}

	timeout := parseTimeout(artifact.Metadata["timeout_seconds"])
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cleanupCtx := context.WithoutCancel(ctx)
	if acquired && s.runtime != nil {
		defer func() {
			if acquired {
				s.warnBestEffort("complete proxy request budget release failed",
					s.runtime.CompleteProxyRequest(cleanupCtx, req.ProxyHandle, responseBytes),
					"proxy_handle", req.ProxyHandle,
					"grant_id", grant.ID,
				)
			}
		}()
	}

	payload, err := s.githubProxy.Execute(ctx, artifact, req.Operation, req.Params)
	responseBytes = int64(len(payload))
	if err != nil {
		return nil, fmt.Errorf("execute github proxy %q operation %q: execute upstream request: %w", req.ProxyHandle, req.Operation, err)
	}
	if acquired && s.runtime != nil {
		if err := s.runtime.CompleteProxyRequest(cleanupCtx, req.ProxyHandle, responseBytes); err != nil {
			if errors.Is(err, core.ErrResourceBudgetExceeded) {
				s.metrics.recordBudgetExhaustion(req.ProxyHandle)
			}
			return nil, fmt.Errorf("execute github proxy %q operation %q: release proxy request budget: %w", req.ProxyHandle, req.Operation, err)
		}
		acquired = false
	}

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:     s.ids.New("evt"),
		TenantID:    artifact.TenantID,
		EventType:   "proxy.executed",
		SessionID:   session.ID,
		RunID:       session.RunID,
		GrantID:     grant.ID,
		Actor:       session.AgentID,
		Tool:        grant.Tool,
		Capability:  grant.Capability,
		ResourceRef: grant.ResourceRef,
		Metadata: map[string]any{
			"operation": req.Operation,
			"bytes":     len(payload),
		},
		CreatedAt: s.clock.Now(),
	})

	return &core.ExecuteGitHubProxyResponse{
		Payload:     payload,
		ContentType: "application/json",
	}, nil
}

func (s *Service) RegisterBrowserRelay(ctx context.Context, req *core.RegisterBrowserRelayRequest) (*core.RegisterBrowserRelayResponse, error) {
	if req == nil || req.SessionToken == "" || req.KeyID == "" || req.PublicKey == "" || req.Origin == "" || req.TabID == "" {
		return nil, fmt.Errorf("%w: session_token, key_id, public_key, origin, and tab_id are required", core.ErrInvalidRequest)
	}
	if s.runtime == nil {
		return nil, fmt.Errorf("%w: runtime store is not configured", core.ErrInvalidRequest)
	}
	if _, err := url.ParseRequestURI(req.Origin); err != nil {
		return nil, fmt.Errorf("%w: invalid origin %q", core.ErrInvalidRequest, req.Origin)
	}

	session, _, err := s.loadActiveSession(ctx, req.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("register browser relay for origin %q: load active session: %w", req.Origin, err)
	}

	relay := &core.BrowserRelaySession{
		SessionID: session.ID,
		TenantID:  session.TenantID,
		KeyID:     req.KeyID,
		PublicKey: req.PublicKey,
		Origin:    req.Origin,
		TabID:     req.TabID,
		Selectors: cloneStringMap(req.Selectors),
		ExpiresAt: session.ExpiresAt,
		CreatedAt: s.clock.Now(),
	}
	if err := s.runtime.SaveRelaySession(ctx, relay); err != nil {
		return nil, fmt.Errorf("register browser relay for session %q: save relay session: %w", session.ID, err)
	}

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:   s.ids.New("evt"),
		TenantID:  session.TenantID,
		EventType: "browser.relay_registered",
		SessionID: session.ID,
		RunID:     session.RunID,
		Actor:     session.AgentID,
		CreatedAt: s.clock.Now(),
	})

	return &core.RegisterBrowserRelayResponse{
		SessionID: session.ID,
		KeyID:     req.KeyID,
		ExpiresAt: relay.ExpiresAt,
	}, nil
}

func (s *Service) UnwrapArtifact(ctx context.Context, req *core.UnwrapArtifactRequest) (*core.UnwrapArtifactResponse, error) {
	if req == nil || req.SessionToken == "" || req.ArtifactID == "" {
		return nil, fmt.Errorf("%w: session_token and artifact_id are required", core.ErrInvalidRequest)
	}

	session, _, err := s.loadActiveSession(ctx, req.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("unwrap artifact %q: load active session: %w", req.ArtifactID, err)
	}
	artifact, err := s.repo.GetArtifact(ctx, req.ArtifactID)
	if err != nil {
		return nil, fmt.Errorf("unwrap artifact %q: load artifact: %w", req.ArtifactID, err)
	}
	if artifact.Kind != core.ArtifactKindWrappedSecret {
		return nil, fmt.Errorf("%w: artifact %q is not wrapped", core.ErrForbidden, artifact.ID)
	}
	if artifact.SessionID != "" && artifact.SessionID != session.ID {
		return nil, fmt.Errorf("%w: artifact does not belong to session", core.ErrForbidden)
	}
	if !artifact.ExpiresAt.IsZero() && s.clock.Now().After(artifact.ExpiresAt) {
		return nil, fmt.Errorf("%w: artifact expired", core.ErrForbidden)
	}

	if artifact.ConnectorKind == "browser" {
		if s.runtime == nil {
			return nil, fmt.Errorf("%w: runtime store is not configured", core.ErrInvalidRequest)
		}
		relay, err := s.runtime.GetRelaySession(ctx, session.ID)
		if err != nil {
			return nil, fmt.Errorf("unwrap artifact %q: load browser relay session %q: %w", req.ArtifactID, session.ID, err)
		}
		if relay.KeyID != req.KeyID || relay.Origin != req.Origin || relay.TabID != req.TabID {
			return nil, fmt.Errorf("%w: relay binding mismatch", core.ErrForbidden)
		}
		if boundOrigin := artifact.RecipientBinding["origin"]; boundOrigin != "" && boundOrigin != req.Origin {
			return nil, fmt.Errorf("%w: artifact origin mismatch", core.ErrForbidden)
		}
	}

	usedArtifact, err := s.repo.UseArtifact(ctx, req.ArtifactID, s.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("unwrap artifact %q: mark artifact used: %w", req.ArtifactID, err)
	}
	s.metrics.recordArtifactTransition(artifact.State, usedArtifact.State, usedArtifact.ConnectorKind)
	s.metrics.recordArtifactUnwrap(usedArtifact.ConnectorKind)

	fields := make([]core.BrowserFillField, 0, len(usedArtifact.SecretData))
	if artifact.ConnectorKind == "browser" {
		fields = buildBrowserFields(usedArtifact)
	} else {
		for key, value := range usedArtifact.SecretData {
			fields = append(fields, core.BrowserFillField{Name: key, Value: value})
		}
	}
	sort.Slice(fields, func(i int, j int) bool { return fields[i].Name < fields[j].Name })

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:   s.ids.New("evt"),
		TenantID:  session.TenantID,
		EventType: "artifact.unwrapped",
		SessionID: session.ID,
		RunID:     session.RunID,
		GrantID:   artifact.GrantID,
		Actor:     session.AgentID,
		CreatedAt: s.clock.Now(),
	})

	return &core.UnwrapArtifactResponse{
		ArtifactID: usedArtifact.ID,
		Origin:     usedArtifact.Metadata["origin"],
		AutoSubmit: false,
		Fields:     fields,
	}, nil
}

func (s *Service) issueGrant(ctx context.Context, session *core.Session, grant *core.Grant, resource core.ResourceDescriptor, connector core.Connector) (*core.RequestGrantResponse, error) {
	artifact, err := connector.Issue(ctx, core.IssueRequest{
		Session:  session,
		Grant:    grant,
		Resource: resource,
	})
	if err != nil {
		return nil, fmt.Errorf("issue grant %q: connector %q issue: %w", grant.ID, connector.Kind(), err)
	}

	adapter, ok := s.deliveries[grant.DeliveryMode]
	if !ok {
		return nil, fmt.Errorf("%w: no delivery adapter for mode %q", core.ErrInvalidRequest, grant.DeliveryMode)
	}

	delivery, err := adapter.Deliver(ctx, artifact, session, grant)
	if err != nil {
		return nil, fmt.Errorf("issue grant %q: deliver artifact via %q: %w", grant.ID, grant.DeliveryMode, err)
	}

	grant.State = core.GrantStateIssued
	grant.Delivery = delivery
	if artifact.ExpiresAt.IsZero() {
		artifact.ExpiresAt = grant.ExpiresAt
	}

	artifactID := delivery.ArtifactID
	if artifactID == "" {
		artifactID = s.ids.New("art")
	}
	grant.ArtifactRef = &artifactID

	storedArtifact := &core.Artifact{
		ID:            artifactID,
		TenantID:      session.TenantID,
		SessionID:     session.ID,
		GrantID:       grant.ID,
		Handle:        delivery.Handle,
		Kind:          artifact.Kind,
		ConnectorKind: connector.Kind(),
		SecretData:    artifact.SecretData,
		Metadata:      cloneStringMap(artifact.Metadata),
		SingleUse:     artifact.Kind == core.ArtifactKindWrappedSecret,
		State:         core.ArtifactStateIssued,
		ExpiresAt:     artifact.ExpiresAt,
		CreatedAt:     s.clock.Now(),
	}
	if connector.Kind() == "browser" && s.runtime != nil {
		if relay, err := s.runtime.GetRelaySession(ctx, session.ID); err == nil {
			storedArtifact.RecipientBinding = map[string]string{
				"key_id": relay.KeyID,
				"origin": relay.Origin,
				"tab_id": relay.TabID,
			}
		}
	}
	if err := s.repo.SaveArtifact(ctx, storedArtifact); err != nil {
		return nil, fmt.Errorf("issue grant %q: save artifact %q: %w", grant.ID, storedArtifact.ID, err)
	}
	s.metrics.recordArtifactCreated(storedArtifact.ConnectorKind)
	if delivery.Handle != "" && s.runtime != nil {
		if err := s.runtime.RegisterProxyHandle(ctx, delivery.Handle, budgetFromMetadata(artifact.Metadata), artifact.ExpiresAt); err != nil {
			return nil, fmt.Errorf("issue grant %q: register proxy handle %q: %w", grant.ID, delivery.Handle, err)
		}
	}
	if err := s.repo.SaveGrant(ctx, grant); err != nil {
		return nil, fmt.Errorf("issue grant %q: save issued grant: %w", grant.ID, err)
	}
	if grant.ApprovalID != nil {
		s.metrics.recordGrantTransition(grant.State)
	} else {
		s.metrics.recordGrantCreated(grant.State, grant.EffectiveTTL)
	}

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:     s.ids.New("evt"),
		TenantID:    session.TenantID,
		EventType:   "artifact.issued",
		SessionID:   session.ID,
		RunID:       session.RunID,
		GrantID:     grant.ID,
		Actor:       session.AgentID,
		Tool:        grant.Tool,
		Capability:  grant.Capability,
		ResourceRef: grant.ResourceRef,
		CreatedAt:   s.clock.Now(),
	})
	s.appendAudit(ctx, &core.AuditEvent{
		EventID:     s.ids.New("evt"),
		TenantID:    session.TenantID,
		EventType:   "artifact.delivered",
		SessionID:   session.ID,
		RunID:       session.RunID,
		GrantID:     grant.ID,
		Actor:       session.AgentID,
		Tool:        grant.Tool,
		Capability:  grant.Capability,
		ResourceRef: grant.ResourceRef,
		CreatedAt:   s.clock.Now(),
	})

	return &core.RequestGrantResponse{
		GrantID:   grant.ID,
		State:     grant.State,
		Delivery:  delivery,
		ExpiresAt: grant.ExpiresAt,
	}, nil
}

func (s *Service) loadActiveSession(ctx context.Context, raw string) (*core.Session, *core.SessionClaims, error) {
	if raw == "" {
		return nil, nil, fmt.Errorf("%w: session token is required", core.ErrInvalidRequest)
	}

	claims, err := s.sessionTokens.Verify(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("load active session: verify session token: %w", err)
	}
	session, err := s.repo.GetSession(ctx, claims.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("load active session %q: load session: %w", claims.SessionID, err)
	}
	if session.State != core.SessionStateActive {
		return nil, nil, fmt.Errorf("%w: session is not active", core.ErrForbidden)
	}
	if s.clock.Now().After(session.ExpiresAt) {
		previousState := session.State
		session.State = core.SessionStateExpired
		if err := s.repo.SaveSession(ctx, session); err != nil {
			return nil, nil, fmt.Errorf("load active session %q: expire session: %w", session.ID, err)
		}
		s.metrics.recordSessionTransition(previousState, session.State, session.TenantID)
		return nil, nil, fmt.Errorf("%w: session expired", core.ErrForbidden)
	}
	return session, claims, nil
}

func (s *Service) ensureDelegationAllows(session *core.Session, req *core.RequestGrantRequest, resource core.ResourceDescriptor) error {
	if session.Delegation == nil {
		return nil
	}
	delegation := session.Delegation
	if delegation.TenantID != "" && delegation.TenantID != session.TenantID {
		return fmt.Errorf("%w: delegation tenant mismatch", core.ErrForbidden)
	}
	if delegation.AgentID != "" && delegation.AgentID != session.AgentID {
		return fmt.Errorf("%w: delegation agent mismatch", core.ErrForbidden)
	}
	if s.clock.Now().After(delegation.ExpiresAt) {
		return fmt.Errorf("%w: delegation expired", core.ErrForbidden)
	}
	if !contains(delegation.AllowedCapabilities, req.Capability) {
		return fmt.Errorf("%w: delegation does not allow capability", core.ErrForbidden)
	}

	filterKey := resourceFilterKey(resource.Kind)
	if allowed, ok := delegation.ResourceFilters[filterKey]; ok && len(allowed) > 0 && !contains(allowed, resource.Name) {
		return fmt.Errorf("%w: delegation does not allow resource", core.ErrForbidden)
	}
	return nil
}

func (s *Service) appendAudit(ctx context.Context, evt *core.AuditEvent) {
	if s.audit == nil || evt == nil {
		return
	}
	s.warnBestEffort("audit append failed",
		s.audit.Append(ctx, evt),
		"event_id", evt.EventID,
		"event_type", evt.EventType,
		"tenant_id", evt.TenantID,
	)
}

func (s *Service) warnBestEffort(msg string, err error, args ...any) {
	if err == nil {
		return
	}
	args = append(args, "error", err)
	s.logger.Warn(msg, args...)
}

func hashWorkload(workload *core.WorkloadIdentity) string {
	parts := []string{
		string(workload.Type),
		workload.Issuer,
		workload.Subject,
		workload.Audience,
		workload.Namespace,
		workload.ServiceAccount,
	}
	keys := make([]string, 0, len(workload.Attributes))
	for key := range workload.Attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+workload.Attributes[key])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func resourceFilterKey(kind core.ResourceKind) string {
	switch kind {
	case core.ResourceKindGitHubRepo:
		return "repo"
	case core.ResourceKindDBRole:
		return "db_role"
	case core.ResourceKindBrowserOrigin:
		return "origin"
	default:
		return ""
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func budgetFromMetadata(metadata map[string]string) core.ProxyBudget {
	budget := core.ProxyBudget{
		MaxConcurrent: parsePositiveInt(metadata["max_concurrent"]),
		MaxRequests:   parsePositiveInt(metadata["max_requests"]),
		MaxBytes:      parsePositiveInt64(metadata["max_bytes"]),
		Timeout:       parseTimeout(metadata["timeout_seconds"]),
	}
	if budget.Timeout == 0 {
		budget.Timeout = 15 * time.Second
	}
	return budget
}

func parsePositiveInt(raw string) int {
	if raw == "" {
		return 0
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0
	}
	return value
}

func parsePositiveInt64(raw string) int64 {
	if raw == "" {
		return 0
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0
	}
	return value
}

func parseTimeout(raw string) time.Duration {
	seconds := parsePositiveInt(raw)
	if seconds == 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func operationAllowed(raw string, operation string) bool {
	if raw == "" {
		return false
	}
	for _, item := range strings.Split(raw, ",") {
		if strings.TrimSpace(item) == operation {
			return true
		}
	}
	return false
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func buildBrowserFields(artifact *core.Artifact) []core.BrowserFillField {
	fieldNames := []string{"username", "password", "otp"}
	fields := make([]core.BrowserFillField, 0, len(fieldNames))
	for _, name := range fieldNames {
		value := artifact.SecretData[name]
		if value == "" {
			continue
		}
		selector := artifact.Metadata["selector_"+name]
		if selector == "" {
			continue
		}
		fields = append(fields, core.BrowserFillField{
			Name:     name,
			Selector: selector,
			Value:    value,
		})
	}
	return fields
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}

type timeIDs struct{}

func (timeIDs) New(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}
