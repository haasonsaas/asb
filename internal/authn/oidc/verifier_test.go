package oidc_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/evalops/asb/internal/authn/oidc"
	"github.com/evalops/asb/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

func newTestVerifier(t *testing.T, publicKey ed25519.PublicKey, prefixes []string) *oidc.Verifier {
	t.Helper()

	verifier, err := oidc.NewVerifier(oidc.Config{
		Issuer:                 "https://token.actions.githubusercontent.com",
		Audience:               "asb-control-plane",
		AllowedSubjectPrefixes: prefixes,
		Keyfunc: func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return verifier
}

func TestVerifier_VerifyGitHubActionsToken(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":                   "https://token.actions.githubusercontent.com",
		"sub":                   "repo:evalops/asb:ref:refs/heads/main",
		"aud":                   "asb-control-plane",
		"exp":                   time.Now().Add(5 * time.Minute).Unix(),
		"iat":                   time.Now().Add(-time.Minute).Unix(),
		"actor":                 "haasonsaas",
		"repository":            "evalops/asb",
		"repository_owner":      "evalops",
		"job_workflow_ref":      "evalops/asb/.github/workflows/ci.yml@refs/heads/main",
		"sha":                   "abc123",
		"ref":                   "refs/heads/main",
		"run_id":                float64(42),
		"run_attempt":           float64(2),
		"runner_environment":    "github-hosted",
		"repository_visibility": "private",
	})
	raw, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier := newTestVerifier(t, publicKey, []string{"repo:evalops/"})

	identity, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindOIDCJWT,
		Token: raw,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if identity.Type != core.WorkloadIdentityTypeOIDC {
		t.Fatalf("Type = %q, want %q", identity.Type, core.WorkloadIdentityTypeOIDC)
	}
	if identity.Subject != "repo:evalops/asb:ref:refs/heads/main" {
		t.Fatalf("Subject = %q, want GitHub Actions subject", identity.Subject)
	}
	if identity.Attributes["repository"] != "evalops/asb" {
		t.Fatalf("repository = %q, want evalops/asb", identity.Attributes["repository"])
	}
	if identity.Attributes["run_id"] != "42" {
		t.Fatalf("run_id = %q, want 42", identity.Attributes["run_id"])
	}
}

func TestVerifier_RejectsUnexpectedSubjectPrefix(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:other-org/repo:ref:refs/heads/main",
		"aud": "asb-control-plane",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	raw, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier := newTestVerifier(t, publicKey, []string{"repo:evalops/"})

	if _, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindOIDCJWT,
		Token: raw,
	}); err == nil {
		t.Fatal("Verify() error = nil, want non-nil")
	}
}

func TestVerifier_AllowsAnySubjectWhenPrefixesUnset(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:other-org/repo:ref:refs/heads/main",
		"aud": "asb-control-plane",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	})
	raw, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier := newTestVerifier(t, publicKey, nil)
	if _, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindOIDCJWT,
		Token: raw,
	}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifier_RejectsExpiredToken(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:evalops/asb:ref:refs/heads/main",
		"aud": "asb-control-plane",
		"exp": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Add(-2 * time.Minute).Unix(),
	})
	raw, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier := newTestVerifier(t, publicKey, []string{"repo:evalops/"})
	if _, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindOIDCJWT,
		Token: raw,
	}); err == nil {
		t.Fatal("Verify() error = nil, want expired token failure")
	}
}

func TestVerifier_RejectsTokenBeforeNotBefore(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:evalops/asb:ref:refs/heads/main",
		"aud": "asb-control-plane",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
		"nbf": time.Now().Add(time.Minute).Unix(),
	})
	raw, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier := newTestVerifier(t, publicKey, []string{"repo:evalops/"})
	if _, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindOIDCJWT,
		Token: raw,
	}); err == nil {
		t.Fatal("Verify() error = nil, want not-before validation failure")
	}
}

func TestVerifier_RejectsUnexpectedSigningMethod(t *testing.T) {
	t.Parallel()

	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:evalops/asb:ref:refs/heads/main",
		"aud": "asb-control-plane",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	raw, err := token.SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier := newTestVerifier(t, publicKey, []string{"repo:evalops/"})
	if _, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindOIDCJWT,
		Token: raw,
	}); err == nil {
		t.Fatal("Verify() error = nil, want signing-method failure")
	}
}
