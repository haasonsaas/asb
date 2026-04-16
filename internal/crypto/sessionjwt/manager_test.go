package sessionjwt

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/evalops/asb/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

func newTestManager(t *testing.T, now time.Time) (*Manager, ed25519.PrivateKey) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	manager, err := NewManager(privateKey, WithNowFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager, privateKey
}

func TestManagerSignAddsStandardClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 15, 22, 0, 0, 0, time.UTC)
	_, privateKey := newTestManager(t, now)
	manager, err := NewManager(privateKey, WithIssuer("asb.example"), WithNowFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	raw, err := manager.Sign(&core.Session{
		ID:        "sess_123",
		TokenID:   "tok_123",
		TenantID:  "t_acme",
		AgentID:   "agent_pr_reviewer",
		RunID:     "run_7f9",
		CreatedAt: now,
		ExpiresAt: now.Add(15 * time.Minute),
		WorkloadIdentity: core.WorkloadIdentity{
			Subject: "system:serviceaccount:agents:runner",
		},
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parsed, err := jwt.ParseWithClaims(raw, &claims{}, func(token *jwt.Token) (any, error) {
		return manager.publicKey, nil
	}, jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("ParseWithClaims() error = %v", err)
	}
	tokenClaims, ok := parsed.Claims.(*claims)
	if !ok {
		t.Fatalf("claims type = %T, want *claims", parsed.Claims)
	}
	if tokenClaims.ID != "tok_123" {
		t.Fatalf("jti = %q, want tok_123", tokenClaims.ID)
	}
	if tokenClaims.Issuer != "asb.example" {
		t.Fatalf("issuer = %q, want asb.example", tokenClaims.Issuer)
	}
	if tokenClaims.NotBefore == nil {
		t.Fatal("nbf = nil, want non-nil")
	}
	if got := tokenClaims.NotBefore.Time; !got.Equal(now.Add(-defaultClockSkew)) {
		t.Fatalf("nbf = %s, want %s", got, now.Add(-defaultClockSkew))
	}

	sessionClaims, err := manager.Verify(raw)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if sessionClaims.TokenID != "tok_123" {
		t.Fatalf("TokenID = %q, want tok_123", sessionClaims.TokenID)
	}
}

func TestManagerVerifyRejectsMissingJTI(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 15, 22, 0, 0, 0, time.UTC)
	manager, privateKey := newTestManager(t, now)

	raw, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		SessionID: "sess_123",
		TenantID:  "t_acme",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-defaultClockSkew)),
			Issuer:    defaultIssuer,
		},
	}).SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	if _, err := manager.Verify(raw); err == nil || !strings.Contains(err.Error(), "missing jti") {
		t.Fatalf("Verify() error = %v, want missing jti", err)
	}
}

func TestManagerVerifyRejectsTokenBeforeNotBefore(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 15, 22, 0, 0, 0, time.UTC)
	manager, privateKey := newTestManager(t, now)

	raw, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		SessionID: "sess_123",
		TenantID:  "t_acme",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "tok_123",
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(time.Minute)),
			Issuer:    defaultIssuer,
		},
	}).SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	if _, err := manager.Verify(raw); err == nil || !strings.Contains(err.Error(), "token is not valid yet") {
		t.Fatalf("Verify() error = %v, want not-before validation failure", err)
	}
}

func TestManagerVerifyRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 15, 22, 0, 0, 0, time.UTC)
	manager, privateKey := newTestManager(t, now)

	raw, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		SessionID: "sess_123",
		TenantID:  "t_acme",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "tok_123",
			ExpiresAt: jwt.NewNumericDate(now.Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-3 * time.Minute)),
			Issuer:    defaultIssuer,
		},
	}).SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	if _, err := manager.Verify(raw); err == nil || !strings.Contains(err.Error(), "token is expired") {
		t.Fatalf("Verify() error = %v, want expiration failure", err)
	}
}

func TestManagerVerifyRejectsUnexpectedSigningMethod(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 15, 22, 0, 0, 0, time.UTC)
	manager, _ := newTestManager(t, now)

	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		SessionID: "sess_123",
		TenantID:  "t_acme",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "tok_123",
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-defaultClockSkew)),
			Issuer:    defaultIssuer,
		},
	}).SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	if _, err := manager.Verify(raw); err == nil || !strings.Contains(err.Error(), "unexpected signing method") {
		t.Fatalf("Verify() error = %v, want signing-method failure", err)
	}
}

func TestManagerVerifyRejectsMissingSessionID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 15, 22, 0, 0, 0, time.UTC)
	manager, privateKey := newTestManager(t, now)

	raw, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		TenantID: "t_acme",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "tok_123",
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-defaultClockSkew)),
			Issuer:    defaultIssuer,
		},
	}).SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	if _, err := manager.Verify(raw); err == nil || !strings.Contains(err.Error(), "missing required session claims") {
		t.Fatalf("Verify() error = %v, want missing required session claims", err)
	}
}

func TestManagerVerifyRejectsMissingTenantID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 15, 22, 0, 0, 0, time.UTC)
	manager, privateKey := newTestManager(t, now)

	raw, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		SessionID: "sess_123",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "tok_123",
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-defaultClockSkew)),
			Issuer:    defaultIssuer,
		},
	}).SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	if _, err := manager.Verify(raw); err == nil || !strings.Contains(err.Error(), "missing required session claims") {
		t.Fatalf("Verify() error = %v, want missing required session claims", err)
	}
}

func TestManagerVerifyRejectsTamperedToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 15, 22, 0, 0, 0, time.UTC)
	manager, privateKey := newTestManager(t, now)

	raw, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{
		SessionID: "sess_123",
		TenantID:  "t_acme",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "tok_123",
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-defaultClockSkew)),
			Issuer:    defaultIssuer,
		},
	}).SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("expected jwt token, got %q", raw)
	}
	signature := []byte(parts[2])
	if len(signature) == 0 {
		t.Fatalf("expected signature segment, got %q", raw)
	}
	if signature[0] == 'A' {
		signature[0] = 'B'
	} else {
		signature[0] = 'A'
	}
	tampered := strings.Join([]string{parts[0], parts[1], string(signature)}, ".")
	if _, err := manager.Verify(tampered); err == nil {
		t.Fatal("Verify() error = nil, want tampered token failure")
	}
}
