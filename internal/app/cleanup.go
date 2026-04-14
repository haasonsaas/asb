package app

import (
	"context"
	"fmt"

	"github.com/evalops/asb/internal/core"
)

type CleanupStats struct {
	ApprovalsExpired int
	SessionsExpired  int
	GrantsExpired    int
	ArtifactsExpired int
}

func (s *Service) RunCleanupOnce(ctx context.Context, limit int) (*CleanupStats, error) {
	stats := &CleanupStats{}
	now := s.clock.Now()

	approvals, err := s.repo.ListExpiredApprovals(ctx, now, limit)
	if err != nil {
		return nil, fmt.Errorf("run cleanup: list expired approvals: %w", err)
	}
	for _, approval := range approvals {
		if err := s.expireApproval(ctx, approval); err != nil {
			return nil, fmt.Errorf("run cleanup: expire approval %q: %w", approval.ID, err)
		}
		stats.ApprovalsExpired++
	}

	sessions, err := s.repo.ListExpiredSessions(ctx, now, limit)
	if err != nil {
		return nil, fmt.Errorf("run cleanup: list expired sessions: %w", err)
	}
	for _, session := range sessions {
		if err := s.expireSession(ctx, session, stats); err != nil {
			return nil, fmt.Errorf("run cleanup: expire session %q: %w", session.ID, err)
		}
	}

	grants, err := s.repo.ListExpiredGrants(ctx, now, limit)
	if err != nil {
		return nil, fmt.Errorf("run cleanup: list expired grants: %w", err)
	}
	for _, grant := range grants {
		session, err := s.repo.GetSession(ctx, grant.SessionID)
		if err != nil {
			return nil, fmt.Errorf("run cleanup: load session %q for expired grant %q: %w", grant.SessionID, grant.ID, err)
		}
		if session.State != core.SessionStateActive {
			continue
		}
		if err := s.transitionGrantState(ctx, session, grant, core.GrantStateExpired, "grant_expired"); err != nil {
			return nil, fmt.Errorf("run cleanup: expire grant %q: %w", grant.ID, err)
		}
		stats.GrantsExpired++
	}

	artifacts, err := s.repo.ListExpiredArtifacts(ctx, now, limit)
	if err != nil {
		return nil, fmt.Errorf("run cleanup: list expired artifacts: %w", err)
	}
	for _, artifact := range artifacts {
		if artifact.State == core.ArtifactStateExpired {
			continue
		}
		previousState := artifact.State
		artifact.State = core.ArtifactStateExpired
		if err := s.repo.SaveArtifact(ctx, artifact); err != nil {
			return nil, fmt.Errorf("run cleanup: save expired artifact %q: %w", artifact.ID, err)
		}
		s.metrics.recordArtifactTransition(previousState, artifact.State, artifact.ConnectorKind)
		stats.ArtifactsExpired++
		s.appendAudit(ctx, &core.AuditEvent{
			EventID:   s.ids.New("evt"),
			TenantID:  artifact.TenantID,
			EventType: "artifact.expired",
			SessionID: artifact.SessionID,
			GrantID:   artifact.GrantID,
			CreatedAt: now,
		})
	}

	return stats, nil
}

func (s *Service) expireApproval(ctx context.Context, approval *core.Approval) error {
	if approval.State != core.ApprovalStatePending {
		return nil
	}
	approval.State = core.ApprovalStateExpired
	if err := s.repo.SaveApproval(ctx, approval); err != nil {
		return fmt.Errorf("expire approval %q: save approval: %w", approval.ID, err)
	}
	s.metrics.recordApprovalTransition(approval.State, s.clock.Now().Sub(approval.CreatedAt))

	grant, err := s.repo.GetGrant(ctx, approval.GrantID)
	if err != nil {
		return fmt.Errorf("expire approval %q: load grant %q: %w", approval.ID, approval.GrantID, err)
	}
	if grant.State == core.GrantStatePending {
		grant.State = core.GrantStateExpired
		if err := s.repo.SaveGrant(ctx, grant); err != nil {
			return fmt.Errorf("expire approval %q: save expired grant %q: %w", approval.ID, grant.ID, err)
		}
		s.metrics.recordGrantTransition(grant.State)
	}

	s.appendAudit(ctx, &core.AuditEvent{
		EventID:   s.ids.New("evt"),
		TenantID:  approval.TenantID,
		EventType: "approval.expired",
		GrantID:   approval.GrantID,
		Actor:     approval.RequestedBy,
		CreatedAt: s.clock.Now(),
	})
	return nil
}

func (s *Service) expireSession(ctx context.Context, session *core.Session, stats *CleanupStats) error {
	if session.State != core.SessionStateActive {
		return nil
	}
	grants, err := s.repo.ListGrantsBySession(ctx, session.ID)
	if err != nil {
		return fmt.Errorf("expire session %q: list grants: %w", session.ID, err)
	}
	for _, grant := range grants {
		switch grant.State {
		case core.GrantStateRevoked, core.GrantStateDenied, core.GrantStateExpired:
			continue
		}
		if err := s.transitionGrantState(ctx, session, grant, core.GrantStateExpired, "session_expired"); err != nil {
			return fmt.Errorf("expire session %q: expire grant %q: %w", session.ID, grant.ID, err)
		}
		stats.GrantsExpired++
	}
	session.State = core.SessionStateExpired
	if err := s.repo.SaveSession(ctx, session); err != nil {
		return fmt.Errorf("expire session %q: save session: %w", session.ID, err)
	}
	s.metrics.recordSessionTransition(core.SessionStateActive, session.State, session.TenantID)
	stats.SessionsExpired++
	s.appendAudit(ctx, &core.AuditEvent{
		EventID:   s.ids.New("evt"),
		TenantID:  session.TenantID,
		EventType: "session.expired",
		SessionID: session.ID,
		RunID:     session.RunID,
		Actor:     session.AgentID,
		CreatedAt: s.clock.Now(),
	})
	return nil
}

func (s *Service) transitionGrantState(ctx context.Context, session *core.Session, grant *core.Grant, state core.GrantState, reason string) error {
	var (
		artifact *core.Artifact
		err      error
	)
	if grant.ArtifactRef != nil {
		artifact, err = s.repo.GetArtifact(ctx, *grant.ArtifactRef)
		if err != nil {
			return fmt.Errorf("transition grant %q to %q: load artifact %q: %w", grant.ID, state, *grant.ArtifactRef, err)
		}
	}

	if session == nil {
		session, err = s.repo.GetSession(ctx, grant.SessionID)
		if err != nil {
			return fmt.Errorf("transition grant %q to %q: load session %q: %w", grant.ID, state, grant.SessionID, err)
		}
	}

	if state == core.GrantStateRevoked || state == core.GrantStateExpired {
		connector, err := s.connectors.Resolve(ctx, grant.Capability, grant.ResourceRef)
		if err != nil {
			return fmt.Errorf("transition grant %q to %q: resolve connector: %w", grant.ID, state, err)
		}
		if err := connector.Revoke(ctx, core.RevokeRequest{
			Session:  session,
			Grant:    grant,
			Artifact: artifact,
			Reason:   reason,
		}); err != nil {
			return fmt.Errorf("transition grant %q to %q: revoke connector state: %w", grant.ID, state, err)
		}
	}

	grant.State = state
	if err := s.repo.SaveGrant(ctx, grant); err != nil {
		return fmt.Errorf("transition grant %q to %q: save grant: %w", grant.ID, state, err)
	}
	s.metrics.recordGrantTransition(grant.State)

	if artifact != nil {
		previousState := artifact.State
		switch state {
		case core.GrantStateRevoked:
			artifact.State = core.ArtifactStateRevoked
		case core.GrantStateExpired:
			if artifact.State != core.ArtifactStateUsed {
				artifact.State = core.ArtifactStateExpired
			}
		}
		if err := s.repo.SaveArtifact(ctx, artifact); err != nil {
			return fmt.Errorf("transition grant %q to %q: save artifact %q: %w", grant.ID, state, artifact.ID, err)
		}
		s.metrics.recordArtifactTransition(previousState, artifact.State, artifact.ConnectorKind)
	}

	eventType := ""
	switch state {
	case core.GrantStateRevoked:
		eventType = "grant.revoked"
	case core.GrantStateExpired:
		eventType = "grant.expired"
	}
	if eventType != "" {
		s.appendAudit(ctx, &core.AuditEvent{
			EventID:     s.ids.New("evt"),
			TenantID:    grant.TenantID,
			EventType:   eventType,
			SessionID:   grant.SessionID,
			RunID:       session.RunID,
			GrantID:     grant.ID,
			Actor:       session.AgentID,
			Tool:        grant.Tool,
			Capability:  grant.Capability,
			ResourceRef: grant.ResourceRef,
			Metadata: map[string]any{
				"reason": reason,
			},
			CreatedAt: s.clock.Now(),
		})
	}

	return nil
}

func (s *Service) cleanupSummary(stats *CleanupStats) string {
	if stats == nil {
		return ""
	}
	return fmt.Sprintf("approvals=%d sessions=%d grants=%d artifacts=%d", stats.ApprovalsExpired, stats.SessionsExpired, stats.GrantsExpired, stats.ArtifactsExpired)
}
