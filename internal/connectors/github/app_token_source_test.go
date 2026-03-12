package github_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/haasonsaas/asb/internal/connectors/github"
)

func TestAppTokenSource_TokenForRepoUsesInstallationTokenAndCaches(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)

	installationLookups := 0
	tokenRequests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := parseAppJWT(t, privateKey.Public().(*rsa.PublicKey), r.Header.Get("Authorization"))
		if claims.Issuer != "123" {
			t.Fatalf("issuer = %q, want 123", claims.Issuer)
		}

		switch r.URL.Path {
		case "/repos/acme/widgets/installation":
			installationLookups++
			_, _ = w.Write([]byte(`{"id":987}`))
		case "/app/installations/987/access_tokens":
			tokenRequests++
			_, _ = w.Write([]byte(`{"token":"inst-token","expires_at":"2026-03-12T20:10:00Z"}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	source, err := github.NewAppTokenSource(github.AppTokenSourceConfig{
		AppID:      123,
		PrivateKey: privateKey,
		BaseURL:    server.URL,
		Client:     server.Client(),
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewAppTokenSource() error = %v", err)
	}

	token, err := source.TokenForRepo(context.Background(), "acme", "widgets")
	if err != nil {
		t.Fatalf("TokenForRepo() error = %v", err)
	}
	if token != "inst-token" {
		t.Fatalf("token = %q, want inst-token", token)
	}

	cachedToken, err := source.TokenForRepo(context.Background(), "acme", "widgets")
	if err != nil {
		t.Fatalf("TokenForRepo() cached error = %v", err)
	}
	if cachedToken != "inst-token" {
		t.Fatalf("cached token = %q, want inst-token", cachedToken)
	}
	if installationLookups != 1 || tokenRequests != 1 {
		t.Fatalf("lookups/requests = %d/%d, want 1/1", installationLookups, tokenRequests)
	}
}

func parseAppJWT(t *testing.T, publicKey *rsa.PublicKey, authorization string) *jwt.RegisteredClaims {
	t.Helper()

	const prefix = "Bearer "
	if len(authorization) <= len(prefix) || authorization[:len(prefix)] != prefix {
		t.Fatalf("authorization = %q, want bearer token", authorization)
	}
	token := authorization[len(prefix):]
	parsed, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims() error = %v", err)
	}
	claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok || !parsed.Valid {
		t.Fatalf("parsed claims = %#v, valid=%v", parsed.Claims, parsed.Valid)
	}
	return claims
}
