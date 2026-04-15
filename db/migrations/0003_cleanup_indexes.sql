CREATE INDEX IF NOT EXISTS idx_sessions_state_expires
    ON sessions (state, expires_at);

CREATE INDEX IF NOT EXISTS idx_grants_session_id
    ON grants (session_id);

CREATE INDEX IF NOT EXISTS idx_grants_state_expires
    ON grants (state, expires_at);

CREATE INDEX IF NOT EXISTS idx_approvals_state_expires
    ON approvals (state, expires_at);

CREATE INDEX IF NOT EXISTS idx_artifacts_state_expires
    ON artifacts (state, expires_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON audit_events (created_at);
