package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/haasonsaas/asb/internal/core"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type queryable interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Repository struct {
	db queryable
}

func NewRepository(db queryable) *Repository {
	return &Repository{db: db}
}

func (r *Repository) SaveSession(ctx context.Context, session *core.Session) error {
	workloadID := session.ID + "_workload"
	workloadJSON, err := json.Marshal(map[string]any{
		"audience":        session.WorkloadIdentity.Audience,
		"namespace":       session.WorkloadIdentity.Namespace,
		"service_account": session.WorkloadIdentity.ServiceAccount,
		"attributes":      session.WorkloadIdentity.Attributes,
	})
	if err != nil {
		return err
	}
	if _, err := r.db.Exec(ctx, `
		INSERT INTO tenants (id, name, state, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, state = EXCLUDED.state
	`, session.TenantID, session.TenantID, "active", session.CreatedAt); err != nil {
		return err
	}
	if _, err := r.db.Exec(ctx, `
		INSERT INTO workloads (id, tenant_id, identity_type, subject, issuer, metadata_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET metadata_json = EXCLUDED.metadata_json
	`, workloadID, session.TenantID, string(session.WorkloadIdentity.Type), session.WorkloadIdentity.Subject, session.WorkloadIdentity.Issuer, workloadJSON, session.CreatedAt); err != nil {
		return err
	}

	var delegationID any
	if session.Delegation != nil {
		delegationID = session.Delegation.ID
		claimsJSON, err := json.Marshal(map[string]any{
			"allowed_capabilities": session.Delegation.AllowedCapabilities,
			"resource_filters":     session.Delegation.ResourceFilters,
		})
		if err != nil {
			return err
		}
		if _, err := r.db.Exec(ctx, `
			INSERT INTO delegations (id, tenant_id, issuer, subject, claims_json, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET claims_json = EXCLUDED.claims_json, expires_at = EXCLUDED.expires_at
		`, session.Delegation.ID, session.TenantID, session.Delegation.Issuer, session.Delegation.Subject, claimsJSON, session.Delegation.ExpiresAt, session.CreatedAt); err != nil {
			return err
		}
	}

	toolContextJSON, err := json.Marshal(session.ToolContext)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO sessions (id, tenant_id, workload_id, delegation_id, agent_id, run_id, tool_context_json, workload_hash, state, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			delegation_id = EXCLUDED.delegation_id,
			tool_context_json = EXCLUDED.tool_context_json,
			workload_hash = EXCLUDED.workload_hash,
			state = EXCLUDED.state,
			expires_at = EXCLUDED.expires_at
	`, session.ID, session.TenantID, workloadID, delegationID, session.AgentID, session.RunID, toolContextJSON, session.WorkloadHash, string(session.State), session.ExpiresAt, session.CreatedAt)
	return err
}

func (r *Repository) GetSession(ctx context.Context, sessionID string) (*core.Session, error) {
	var (
		session              core.Session
		workloadType         string
		workloadSubject      string
		workloadIssuer       string
		workloadJSON         []byte
		toolContextJSON      []byte
		delegationID         *string
		delegationIssuer     *string
		delegationSubject    *string
		delegationClaimsJSON []byte
		delegationExpiresAt  *time.Time
	)

	err := r.db.QueryRow(ctx, `
		SELECT
			s.id, s.tenant_id, s.agent_id, s.run_id, s.tool_context_json, s.workload_hash, s.state, s.expires_at, s.created_at,
			w.identity_type, w.subject, w.issuer, w.metadata_json,
			d.id, d.issuer, d.subject, d.claims_json, d.expires_at
		FROM sessions s
		JOIN workloads w ON w.id = s.workload_id
		LEFT JOIN delegations d ON d.id = s.delegation_id
		WHERE s.id = $1
	`, sessionID).Scan(
		&session.ID, &session.TenantID, &session.AgentID, &session.RunID, &toolContextJSON, &session.WorkloadHash, &session.State, &session.ExpiresAt, &session.CreatedAt,
		&workloadType, &workloadSubject, &workloadIssuer, &workloadJSON,
		&delegationID, &delegationIssuer, &delegationSubject, &delegationClaimsJSON, &delegationExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: session %q", core.ErrNotFound, sessionID)
		}
		return nil, err
	}

	if err := json.Unmarshal(toolContextJSON, &session.ToolContext); err != nil {
		return nil, err
	}
	session.WorkloadIdentity = parseWorkloadIdentity(workloadType, workloadSubject, workloadIssuer, workloadJSON)
	if delegationID != nil {
		delegation := parseDelegation(*delegationID, valueOrEmpty(delegationIssuer), valueOrEmpty(delegationSubject), session.TenantID, session.AgentID, delegationClaimsJSON, delegationExpiresAt)
		session.Delegation = delegation
	}
	return &session, nil
}

func (r *Repository) ListGrantsBySession(ctx context.Context, sessionID string) ([]*core.Grant, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, session_id, tool, capability, resource_ref, delivery_mode, connector_kind, approval_id, artifact_ref, state, requested_ttl_seconds, effective_ttl_seconds, expires_at, created_at, reason
		FROM grants
		WHERE session_id = $1
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []*core.Grant
	for rows.Next() {
		grant, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (r *Repository) ListExpiredSessions(ctx context.Context, before time.Time, limit int) ([]*core.Session, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id
		FROM sessions
		WHERE state = 'active' AND expires_at <= $1
		ORDER BY expires_at ASC
		LIMIT $2
	`, before, normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*core.Session
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			return nil, err
		}
		session, err := r.GetSession(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (r *Repository) SaveGrant(ctx context.Context, grant *core.Grant) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO grants (id, tenant_id, session_id, tool, capability, resource_ref, delivery_mode, connector_kind, approval_id, artifact_ref, state, requested_ttl_seconds, effective_ttl_seconds, expires_at, created_at, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (id) DO UPDATE SET
			approval_id = EXCLUDED.approval_id,
			artifact_ref = EXCLUDED.artifact_ref,
			state = EXCLUDED.state,
			effective_ttl_seconds = EXCLUDED.effective_ttl_seconds,
			expires_at = EXCLUDED.expires_at,
			reason = EXCLUDED.reason
	`, grant.ID, grant.TenantID, grant.SessionID, grant.Tool, grant.Capability, grant.ResourceRef, string(grant.DeliveryMode), grant.ConnectorKind, grant.ApprovalID, grant.ArtifactRef, string(grant.State), int(grant.RequestedTTL.Seconds()), int(grant.EffectiveTTL.Seconds()), grant.ExpiresAt, grant.CreatedAt, grant.Reason)
	return err
}

func (r *Repository) GetGrant(ctx context.Context, grantID string) (*core.Grant, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, session_id, tool, capability, resource_ref, delivery_mode, connector_kind, approval_id, artifact_ref, state, requested_ttl_seconds, effective_ttl_seconds, expires_at, created_at, reason
		FROM grants
		WHERE id = $1
	`, grantID)
	grant, err := scanGrant(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: grant %q", core.ErrNotFound, grantID)
		}
		return nil, err
	}
	return grant, nil
}

func (r *Repository) ListExpiredGrants(ctx context.Context, before time.Time, limit int) ([]*core.Grant, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, session_id, tool, capability, resource_ref, delivery_mode, connector_kind, approval_id, artifact_ref, state, requested_ttl_seconds, effective_ttl_seconds, expires_at, created_at, reason
		FROM grants
		WHERE expires_at <= $1 AND state NOT IN ('revoked', 'denied', 'expired')
		ORDER BY expires_at ASC
		LIMIT $2
	`, before, normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []*core.Grant
	for rows.Next() {
		grant, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (r *Repository) SaveApproval(ctx context.Context, approval *core.Approval) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO approvals (id, tenant_id, grant_id, requested_by, approved_by, reason, comment, state, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			approved_by = EXCLUDED.approved_by,
			comment = EXCLUDED.comment,
			state = EXCLUDED.state,
			expires_at = EXCLUDED.expires_at
	`, approval.ID, approval.TenantID, approval.GrantID, approval.RequestedBy, approval.ApprovedBy, approval.Reason, approval.Comment, string(approval.State), approval.ExpiresAt, approval.CreatedAt)
	return err
}

func (r *Repository) GetApproval(ctx context.Context, approvalID string) (*core.Approval, error) {
	var (
		approval   core.Approval
		approvedBy *string
	)
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, grant_id, requested_by, approved_by, reason, comment, state, expires_at, created_at
		FROM approvals
		WHERE id = $1
	`, approvalID).Scan(
		&approval.ID, &approval.TenantID, &approval.GrantID, &approval.RequestedBy, &approvedBy, &approval.Reason, &approval.Comment, &approval.State, &approval.ExpiresAt, &approval.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: approval %q", core.ErrNotFound, approvalID)
		}
		return nil, err
	}
	approval.ApprovedBy = approvedBy
	return &approval, nil
}

func (r *Repository) ListExpiredApprovals(ctx context.Context, before time.Time, limit int) ([]*core.Approval, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, grant_id, requested_by, approved_by, reason, comment, state, expires_at, created_at
		FROM approvals
		WHERE state = 'pending' AND expires_at <= $1
		ORDER BY expires_at ASC
		LIMIT $2
	`, before, normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var approvals []*core.Approval
	for rows.Next() {
		approval, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, approval)
	}
	return approvals, rows.Err()
}

func (r *Repository) SaveArtifact(ctx context.Context, artifact *core.Artifact) error {
	secretJSON, err := json.Marshal(artifact.SecretData)
	if err != nil {
		return err
	}
	metadataJSON, err := json.Marshal(artifact.Metadata)
	if err != nil {
		return err
	}
	bindingJSON, err := json.Marshal(artifact.RecipientBinding)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO artifacts (id, tenant_id, session_id, grant_id, handle, kind, connector_kind, ciphertext, metadata_json, recipient_binding_json, single_use, state, expires_at, created_at, used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (id) DO UPDATE SET
			handle = EXCLUDED.handle,
			ciphertext = EXCLUDED.ciphertext,
			metadata_json = EXCLUDED.metadata_json,
			recipient_binding_json = EXCLUDED.recipient_binding_json,
			single_use = EXCLUDED.single_use,
			state = EXCLUDED.state,
			expires_at = EXCLUDED.expires_at,
			used_at = EXCLUDED.used_at
	`, artifact.ID, artifact.TenantID, artifact.SessionID, artifact.GrantID, artifact.Handle, string(artifact.Kind), artifact.ConnectorKind, secretJSON, metadataJSON, bindingJSON, artifact.SingleUse, string(artifact.State), artifact.ExpiresAt, artifact.CreatedAt, artifact.UsedAt)
	return err
}

func (r *Repository) GetArtifact(ctx context.Context, artifactID string) (*core.Artifact, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, session_id, grant_id, handle, kind, connector_kind, ciphertext, metadata_json, recipient_binding_json, single_use, state, expires_at, created_at, used_at
		FROM artifacts
		WHERE id = $1
	`, artifactID)
	artifact, err := scanArtifact(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: artifact %q", core.ErrNotFound, artifactID)
		}
		return nil, err
	}
	return artifact, nil
}

func (r *Repository) GetArtifactByHandle(ctx context.Context, handle string) (*core.Artifact, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, session_id, grant_id, handle, kind, connector_kind, ciphertext, metadata_json, recipient_binding_json, single_use, state, expires_at, created_at, used_at
		FROM artifacts
		WHERE handle = $1
	`, handle)
	artifact, err := scanArtifact(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: artifact for handle %q", core.ErrNotFound, handle)
		}
		return nil, err
	}
	return artifact, nil
}

func (r *Repository) UseArtifact(ctx context.Context, artifactID string, usedAt time.Time) (*core.Artifact, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE artifacts SET state = $1, used_at = $2
		WHERE id = $3 AND state <> 'used'
		RETURNING id, tenant_id, session_id, grant_id, handle, kind, connector_kind, ciphertext, metadata_json, recipient_binding_json, single_use, state, expires_at, created_at, used_at
	`, string(core.ArtifactStateUsed), usedAt, artifactID)
	artifact, err := scanArtifact(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: artifact %q already used or not found", core.ErrForbidden, artifactID)
		}
		return nil, err
	}
	return artifact, nil
}

func (r *Repository) ListExpiredArtifacts(ctx context.Context, before time.Time, limit int) ([]*core.Artifact, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, session_id, grant_id, handle, kind, connector_kind, ciphertext, metadata_json, recipient_binding_json, single_use, state, expires_at, created_at, used_at
		FROM artifacts
		WHERE expires_at <= $1 AND state NOT IN ('used', 'revoked', 'expired')
		ORDER BY expires_at ASC
		LIMIT $2
	`, before, normalizeLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var artifacts []*core.Artifact
	for rows.Next() {
		artifact, err := scanArtifact(rows)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, rows.Err()
}

func scanGrant(row interface{ Scan(dest ...any) error }) (*core.Grant, error) {
	var (
		grant            core.Grant
		delivery         string
		state            string
		approvalID       *string
		artifactRef      *string
		requestedSeconds int
		effectiveSeconds int
	)
	err := row.Scan(
		&grant.ID, &grant.TenantID, &grant.SessionID, &grant.Tool, &grant.Capability, &grant.ResourceRef, &delivery, &grant.ConnectorKind, &approvalID, &artifactRef, &state, &requestedSeconds, &effectiveSeconds, &grant.ExpiresAt, &grant.CreatedAt, &grant.Reason,
	)
	if err != nil {
		return nil, err
	}
	grant.DeliveryMode = core.DeliveryMode(delivery)
	grant.State = core.GrantState(state)
	grant.ApprovalID = approvalID
	grant.ArtifactRef = artifactRef
	grant.RequestedTTL = time.Duration(requestedSeconds) * time.Second
	grant.EffectiveTTL = time.Duration(effectiveSeconds) * time.Second
	return &grant, nil
}

func scanArtifact(row interface{ Scan(dest ...any) error }) (*core.Artifact, error) {
	var (
		artifact     core.Artifact
		kind         string
		state        string
		secretJSON   []byte
		metadataJSON []byte
		bindingJSON  []byte
		usedAt       pgtype.Timestamptz
	)
	err := row.Scan(
		&artifact.ID, &artifact.TenantID, &artifact.SessionID, &artifact.GrantID, &artifact.Handle, &kind, &artifact.ConnectorKind, &secretJSON, &metadataJSON, &bindingJSON, &artifact.SingleUse, &state, &artifact.ExpiresAt, &artifact.CreatedAt, &usedAt,
	)
	if err != nil {
		return nil, err
	}
	artifact.Kind = core.ArtifactKind(kind)
	artifact.State = core.ArtifactState(state)
	if usedAt.Valid {
		artifact.UsedAt = &usedAt.Time
	}
	if len(secretJSON) > 0 {
		if err := json.Unmarshal(secretJSON, &artifact.SecretData); err != nil {
			return nil, err
		}
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &artifact.Metadata); err != nil {
			return nil, err
		}
	}
	if len(bindingJSON) > 0 {
		if err := json.Unmarshal(bindingJSON, &artifact.RecipientBinding); err != nil {
			return nil, err
		}
	}
	return &artifact, nil
}

func scanApproval(row interface{ Scan(dest ...any) error }) (*core.Approval, error) {
	var (
		approval   core.Approval
		approvedBy *string
		state      string
	)
	err := row.Scan(
		&approval.ID, &approval.TenantID, &approval.GrantID, &approval.RequestedBy, &approvedBy, &approval.Reason, &approval.Comment, &state, &approval.ExpiresAt, &approval.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	approval.State = core.ApprovalState(state)
	approval.ApprovedBy = approvedBy
	return &approval, nil
}

func parseWorkloadIdentity(identityType string, subject string, issuer string, metadataJSON []byte) core.WorkloadIdentity {
	var metadata struct {
		Audience       string            `json:"audience"`
		Namespace      string            `json:"namespace"`
		ServiceAccount string            `json:"service_account"`
		Attributes     map[string]string `json:"attributes"`
	}
	_ = json.Unmarshal(metadataJSON, &metadata)
	return core.WorkloadIdentity{
		Type:           core.WorkloadIdentityType(identityType),
		Issuer:         issuer,
		Subject:        subject,
		Audience:       metadata.Audience,
		Namespace:      metadata.Namespace,
		ServiceAccount: metadata.ServiceAccount,
		Attributes:     metadata.Attributes,
	}
}

func parseDelegation(id string, issuer string, subject string, tenantID string, agentID string, claimsJSON []byte, expiresAt *time.Time) *core.Delegation {
	var claims struct {
		AllowedCapabilities []string            `json:"allowed_capabilities"`
		ResourceFilters     map[string][]string `json:"resource_filters"`
	}
	_ = json.Unmarshal(claimsJSON, &claims)
	delegation := &core.Delegation{
		ID:                  id,
		Issuer:              issuer,
		Subject:             subject,
		TenantID:            tenantID,
		AgentID:             agentID,
		AllowedCapabilities: claims.AllowedCapabilities,
		ResourceFilters:     claims.ResourceFilters,
	}
	if expiresAt != nil {
		delegation.ExpiresAt = *expiresAt
	}
	return delegation
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	return limit
}
