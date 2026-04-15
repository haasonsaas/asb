package sessionjwt

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/evalops/asb/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

type claims struct {
	SessionID    string   `json:"sid"`
	TenantID     string   `json:"tenant_id"`
	AgentID      string   `json:"agent_id"`
	RunID        string   `json:"run_id"`
	ToolContext  []string `json:"tool_context"`
	WorkloadHash string   `json:"workload_hash"`
	jwt.RegisteredClaims
}

func NewManager(privateKey ed25519.PrivateKey) (*Manager, error) {
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("%w: private key is required", core.ErrInvalidRequest)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &Manager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (m *Manager) Sign(session *core.Session) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		SessionID:    session.ID,
		TenantID:     session.TenantID,
		AgentID:      session.AgentID,
		RunID:        session.RunID,
		ToolContext:  append([]string(nil), session.ToolContext...),
		WorkloadHash: session.WorkloadHash,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(session.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(session.CreatedAt),
			Subject:   session.WorkloadIdentity.Subject,
		},
	})
	return token.SignedString(m.privateKey)
}

func (m *Manager) Verify(raw string) (*core.SessionClaims, error) {
	parsed, err := jwt.ParseWithClaims(raw, &claims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("%w: unexpected signing method %q", core.ErrUnauthorized, token.Method.Alg())
		}
		return m.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrUnauthorized, err)
	}

	tokenClaims, ok := parsed.Claims.(*claims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("%w: invalid session token", core.ErrUnauthorized)
	}

	return &core.SessionClaims{
		SessionID:    tokenClaims.SessionID,
		TenantID:     tokenClaims.TenantID,
		AgentID:      tokenClaims.AgentID,
		RunID:        tokenClaims.RunID,
		ToolContext:  append([]string(nil), tokenClaims.ToolContext...),
		WorkloadHash: tokenClaims.WorkloadHash,
		ExpiresAt:    tokenClaims.ExpiresAt.Time,
	}, nil
}

func (c *claims) Valid() error {
	if c.ExpiresAt == nil {
		return fmt.Errorf("%w: missing exp", core.ErrUnauthorized)
	}
	return jwt.NewValidator(jwt.WithTimeFunc(time.Now)).Validate(c.RegisteredClaims)
}
