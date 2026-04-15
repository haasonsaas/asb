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
	issuer     string
	clockSkew  time.Duration
	now        func() time.Time
}

type Option func(*Manager)

const (
	defaultIssuer    = "asb"
	defaultClockSkew = 30 * time.Second
)

type claims struct {
	SessionID    string   `json:"sid"`
	TenantID     string   `json:"tenant_id"`
	AgentID      string   `json:"agent_id"`
	RunID        string   `json:"run_id"`
	ToolContext  []string `json:"tool_context"`
	WorkloadHash string   `json:"workload_hash"`
	jwt.RegisteredClaims
}

func WithIssuer(issuer string) Option {
	return func(manager *Manager) {
		if issuer != "" {
			manager.issuer = issuer
		}
	}
}

func WithClockSkew(clockSkew time.Duration) Option {
	return func(manager *Manager) {
		if clockSkew >= 0 {
			manager.clockSkew = clockSkew
		}
	}
}

func WithNowFunc(now func() time.Time) Option {
	return func(manager *Manager) {
		if now != nil {
			manager.now = now
		}
	}
}

func NewManager(privateKey ed25519.PrivateKey, options ...Option) (*Manager, error) {
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("%w: private key is required", core.ErrInvalidRequest)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: private key public component is %T, want ed25519.PublicKey", core.ErrInvalidRequest, privateKey.Public())
	}
	manager := &Manager{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     defaultIssuer,
		clockSkew:  defaultClockSkew,
		now:        time.Now,
	}
	for _, option := range options {
		option(manager)
	}
	return manager, nil
}

func (m *Manager) Sign(session *core.Session) (string, error) {
	tokenID := session.TokenID
	if tokenID == "" {
		tokenID = session.ID
	}
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
			NotBefore: jwt.NewNumericDate(session.CreatedAt.Add(-m.clockSkew)),
			Issuer:    m.issuer,
			Subject:   session.WorkloadIdentity.Subject,
			ID:        tokenID,
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
	}, jwt.WithIssuer(m.issuer), jwt.WithIssuedAt(), jwt.WithLeeway(m.clockSkew), jwt.WithTimeFunc(m.now))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrUnauthorized, err)
	}

	tokenClaims, ok := parsed.Claims.(*claims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("%w: invalid session token", core.ErrUnauthorized)
	}
	if tokenClaims.ExpiresAt == nil {
		return nil, fmt.Errorf("%w: missing exp", core.ErrUnauthorized)
	}
	if tokenClaims.NotBefore == nil {
		return nil, fmt.Errorf("%w: missing nbf", core.ErrUnauthorized)
	}
	if tokenClaims.ID == "" {
		return nil, fmt.Errorf("%w: missing jti", core.ErrUnauthorized)
	}
	if tokenClaims.SessionID == "" || tokenClaims.TenantID == "" {
		return nil, fmt.Errorf("%w: missing required session claims", core.ErrUnauthorized)
	}

	return &core.SessionClaims{
		SessionID:    tokenClaims.SessionID,
		TenantID:     tokenClaims.TenantID,
		AgentID:      tokenClaims.AgentID,
		RunID:        tokenClaims.RunID,
		TokenID:      tokenClaims.ID,
		ToolContext:  append([]string(nil), tokenClaims.ToolContext...),
		WorkloadHash: tokenClaims.WorkloadHash,
		ExpiresAt:    tokenClaims.ExpiresAt.Time,
	}, nil
}
