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

	verifier, err := oidc.NewVerifier(oidc.Config{
		Issuer:                 "https://token.actions.githubusercontent.com",
		Audience:               "asb-control-plane",
		AllowedSubjectPrefixes: []string{"repo:evalops/"},
		Keyfunc: func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

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

	verifier, err := oidc.NewVerifier(oidc.Config{
		Issuer:                 "https://token.actions.githubusercontent.com",
		Audience:               "asb-control-plane",
		AllowedSubjectPrefixes: []string{"repo:evalops/"},
		Keyfunc: func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	if _, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindOIDCJWT,
		Token: raw,
	}); err == nil {
		t.Fatal("Verify() error = nil, want non-nil")
	}
}

func TestVerifier_StoresValidatedAudienceForMultiAudienceTokens(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:evalops/asb:ref:refs/heads/main",
		"aud": []string{"some-other-audience", "asb-control-plane"},
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	raw, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier, err := oidc.NewVerifier(oidc.Config{
		Issuer:                 "https://token.actions.githubusercontent.com",
		Audience:               "asb-control-plane",
		AllowedSubjectPrefixes: []string{"repo:evalops/"},
		Keyfunc: func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	identity, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindOIDCJWT,
		Token: raw,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if identity.Audience != "asb-control-plane" {
		t.Fatalf("Audience = %q, want asb-control-plane", identity.Audience)
	}
}
