package app

import (
	"context"
	"fmt"

	"github.com/haasonsaas/asb/internal/core"
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
		return nil, err
	}
	for _, approval := range approvals {
		if err := s.expireApproval(ctx, approval); err != nil {
			return nil, err
		}
		stats.ApprovalsExpired++
	}

	sessions, err := s.repo.ListExpiredSessions(ctx, now, limit)
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if err := s.expireSession(ctx, session, stats); err != nil {
			return nil, err
		}
	}

	grants, err := s.repo.ListExpiredGrants(ctx, now, limit)
	if err != nil {
		return nil, err
	}
	for _, grant := range grants {
		session, err := s.repo.GetSession(ctx, grant.SessionID)
		if err != nil {
			return nil, err
		}
		if session.State != core.SessionStateActive {
			continue
		}
		if err := s.transitionGrantState(ctx, session, grant, core.GrantStateExpired, "grant_expired"); err != nil {
			return nil, err
		}
		stats.GrantsExpired++
	}

	artifacts, err := s.repo.ListExpiredArtifacts(ctx, now, limit)
	if err != nil {
		return nil, err
	}
	for _, artifact := range artifacts {
		if artifact.State == core.ArtifactStateExpired {
			continue
		}
		artifact.State = core.ArtifactStateExpired
		if err := s.repo.SaveArtifact(ctx, artifact); err != nil {
			return nil, err
		}
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
		return err
	}

	grant, err := s.repo.GetGrant(ctx, approval.GrantID)
	if err != nil {
		return err
	}
	if grant.State == core.GrantStatePending {
		grant.State = core.GrantStateExpired
		if err := s.repo.SaveGrant(ctx, grant); err != nil {
			return err
		}
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
		return err
	}
	for _, grant := range grants {
		switch grant.State {
		case core.GrantStateRevoked, core.GrantStateDenied, core.GrantStateExpired:
			continue
		}
		if err := s.transitionGrantState(ctx, session, grant, core.GrantStateExpired, "session_expired"); err != nil {
			return err
		}
		stats.GrantsExpired++
	}
	session.State = core.SessionStateExpired
	if err := s.repo.SaveSession(ctx, session); err != nil {
		return err
	}
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
			return err
		}
	}

	if session == nil {
		session, err = s.repo.GetSession(ctx, grant.SessionID)
		if err != nil {
			return err
		}
	}

	if state == core.GrantStateRevoked || state == core.GrantStateExpired {
		connector, err := s.connectors.Resolve(ctx, grant.Capability, grant.ResourceRef)
		if err != nil {
			return err
		}
		if err := connector.Revoke(ctx, core.RevokeRequest{
			Session:  session,
			Grant:    grant,
			Artifact: artifact,
			Reason:   reason,
		}); err != nil {
			return err
		}
	}

	grant.State = state
	if err := s.repo.SaveGrant(ctx, grant); err != nil {
		return err
	}

	if artifact != nil {
		switch state {
		case core.GrantStateRevoked:
			artifact.State = core.ArtifactStateRevoked
		case core.GrantStateExpired:
			if artifact.State != core.ArtifactStateUsed {
				artifact.State = core.ArtifactStateExpired
			}
		}
		if err := s.repo.SaveArtifact(ctx, artifact); err != nil {
			return err
		}
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
