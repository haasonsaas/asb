package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/haasonsaas/asb/internal/core"
)

type Repository struct {
	mu        sync.RWMutex
	sessions  map[string]*core.Session
	grants    map[string]*core.Grant
	approvals map[string]*core.Approval
	artifacts map[string]*core.Artifact
	handles   map[string]string
}

func NewRepository() *Repository {
	return &Repository{
		sessions:  make(map[string]*core.Session),
		grants:    make(map[string]*core.Grant),
		approvals: make(map[string]*core.Approval),
		artifacts: make(map[string]*core.Artifact),
		handles:   make(map[string]string),
	}
}

func (r *Repository) SaveSession(_ context.Context, session *core.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cp := cloneSession(session)
	r.sessions[session.ID] = &cp
	return nil
}

func (r *Repository) GetSession(_ context.Context, sessionID string) (*core.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	session, ok := r.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("%w: session %q", core.ErrNotFound, sessionID)
	}
	cp := cloneSession(session)
	return &cp, nil
}

func (r *Repository) ListGrantsBySession(_ context.Context, sessionID string) ([]*core.Grant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*core.Grant, 0)
	for _, grant := range r.grants {
		if grant.SessionID != sessionID {
			continue
		}
		cp := cloneGrant(grant)
		out = append(out, &cp)
	}
	return out, nil
}

func (r *Repository) ListExpiredSessions(_ context.Context, before time.Time, limit int) ([]*core.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*core.Session, 0)
	for _, session := range r.sessions {
		if session.State != core.SessionStateActive || session.ExpiresAt.After(before) {
			continue
		}
		cp := cloneSession(session)
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (r *Repository) SaveGrant(_ context.Context, grant *core.Grant) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cp := cloneGrant(grant)
	r.grants[grant.ID] = &cp
	return nil
}

func (r *Repository) GetGrant(_ context.Context, grantID string) (*core.Grant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	grant, ok := r.grants[grantID]
	if !ok {
		return nil, fmt.Errorf("%w: grant %q", core.ErrNotFound, grantID)
	}
	cp := cloneGrant(grant)
	return &cp, nil
}

func (r *Repository) ListExpiredGrants(_ context.Context, before time.Time, limit int) ([]*core.Grant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*core.Grant, 0)
	for _, grant := range r.grants {
		if grant.ExpiresAt.After(before) {
			continue
		}
		switch grant.State {
		case core.GrantStateRevoked, core.GrantStateDenied, core.GrantStateExpired:
			continue
		}
		cp := cloneGrant(grant)
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (r *Repository) SaveApproval(_ context.Context, approval *core.Approval) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cp := *approval
	r.approvals[approval.ID] = &cp
	return nil
}

func (r *Repository) GetApproval(_ context.Context, approvalID string) (*core.Approval, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	approval, ok := r.approvals[approvalID]
	if !ok {
		return nil, fmt.Errorf("%w: approval %q", core.ErrNotFound, approvalID)
	}
	cp := cloneApproval(approval)
	return &cp, nil
}

func (r *Repository) ListExpiredApprovals(_ context.Context, before time.Time, limit int) ([]*core.Approval, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*core.Approval, 0)
	for _, approval := range r.approvals {
		if approval.State != core.ApprovalStatePending || approval.ExpiresAt.After(before) {
			continue
		}
		cp := cloneApproval(approval)
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (r *Repository) SaveArtifact(_ context.Context, artifact *core.Artifact) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cp := cloneArtifact(artifact)
	r.artifacts[artifact.ID] = &cp
	if artifact.Handle != "" {
		r.handles[artifact.Handle] = artifact.ID
	}
	return nil
}

func (r *Repository) GetArtifact(_ context.Context, artifactID string) (*core.Artifact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	artifact, ok := r.artifacts[artifactID]
	if !ok {
		return nil, fmt.Errorf("%w: artifact %q", core.ErrNotFound, artifactID)
	}
	cp := cloneArtifact(artifact)
	return &cp, nil
}

func (r *Repository) GetArtifactByHandle(_ context.Context, handle string) (*core.Artifact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	artifactID, ok := r.handles[handle]
	if !ok {
		return nil, fmt.Errorf("%w: proxy handle %q", core.ErrNotFound, handle)
	}
	artifact, ok := r.artifacts[artifactID]
	if !ok {
		return nil, fmt.Errorf("%w: artifact for handle %q", core.ErrNotFound, handle)
	}
	cp := cloneArtifact(artifact)
	return &cp, nil
}

func (r *Repository) UseArtifact(_ context.Context, artifactID string, usedAt time.Time) (*core.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	artifact, ok := r.artifacts[artifactID]
	if !ok {
		return nil, fmt.Errorf("%w: artifact %q", core.ErrNotFound, artifactID)
	}
	if artifact.SingleUse && artifact.State == core.ArtifactStateUsed {
		return nil, fmt.Errorf("%w: artifact %q already used", core.ErrForbidden, artifactID)
	}
	if !artifact.ExpiresAt.IsZero() && usedAt.After(artifact.ExpiresAt) {
		artifact.State = core.ArtifactStateExpired
		return nil, fmt.Errorf("%w: artifact %q expired", core.ErrForbidden, artifactID)
	}

	artifact.State = core.ArtifactStateUsed
	artifact.UsedAt = &usedAt
	cp := cloneArtifact(artifact)
	return &cp, nil
}

func (r *Repository) ListExpiredArtifacts(_ context.Context, before time.Time, limit int) ([]*core.Artifact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*core.Artifact, 0)
	for _, artifact := range r.artifacts {
		if artifact.ExpiresAt.After(before) {
			continue
		}
		switch artifact.State {
		case core.ArtifactStateUsed, core.ArtifactStateRevoked, core.ArtifactStateExpired:
			continue
		}
		cp := cloneArtifact(artifact)
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func cloneSession(session *core.Session) core.Session {
	cp := *session
	cp.ToolContext = append([]string(nil), session.ToolContext...)
	cp.WorkloadIdentity.Attributes = cloneStringMap(session.WorkloadIdentity.Attributes)
	if session.Delegation != nil {
		delegation := *session.Delegation
		delegation.AllowedCapabilities = append([]string(nil), delegation.AllowedCapabilities...)
		delegation.ResourceFilters = cloneStringSliceMap(delegation.ResourceFilters)
		cp.Delegation = &delegation
	}
	return cp
}

func cloneGrant(grant *core.Grant) core.Grant {
	cp := *grant
	if grant.Delivery != nil {
		delivery := *grant.Delivery
		cp.Delivery = &delivery
	}
	if grant.ApprovalID != nil {
		value := *grant.ApprovalID
		cp.ApprovalID = &value
	}
	if grant.ArtifactRef != nil {
		value := *grant.ArtifactRef
		cp.ArtifactRef = &value
	}
	return cp
}

func cloneApproval(approval *core.Approval) core.Approval {
	cp := *approval
	if approval.ApprovedBy != nil {
		value := *approval.ApprovedBy
		cp.ApprovedBy = &value
	}
	return cp
}

func cloneArtifact(artifact *core.Artifact) core.Artifact {
	cp := *artifact
	cp.SecretData = cloneStringMap(artifact.SecretData)
	cp.Metadata = cloneStringMap(artifact.Metadata)
	cp.RecipientBinding = cloneStringMap(artifact.RecipientBinding)
	return cp
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

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}
