package github_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/evalops/asb/internal/connectors/github"
	"github.com/evalops/asb/internal/core"
	"github.com/golang-jwt/jwt/v5"
	goredis "github.com/redis/go-redis/v9"
)

func TestAppTokenSource_TokenForRepoUsesInstallationTokenAndCaches(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)

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
			_, _ = w.Write([]byte(`{"token":"inst-token","expires_at":"` + now.Add(10*time.Minute).Format(time.RFC3339) + `"}`))
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

func TestAppTokenSource_TokenForRepoRefreshesWhenTokenNearExpiry(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	currentTime := now
	tokenRequests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/widgets/installation":
			_, _ = w.Write([]byte(`{"id":987}`))
		case "/app/installations/987/access_tokens":
			tokenRequests++
			tokenValue := "inst-token-1"
			if tokenRequests > 1 {
				tokenValue = "inst-token-2"
			}
			_, _ = w.Write([]byte(`{"token":"` + tokenValue + `","expires_at":"` + now.Add(6*time.Minute).Format(time.RFC3339) + `"}`))
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
			return currentTime
		},
	})
	if err != nil {
		t.Fatalf("NewAppTokenSource() error = %v", err)
	}

	firstToken, err := source.TokenForRepo(context.Background(), "acme", "widgets")
	if err != nil {
		t.Fatalf("TokenForRepo() first error = %v", err)
	}
	currentTime = now.Add(2 * time.Minute)
	secondToken, err := source.TokenForRepo(context.Background(), "acme", "widgets")
	if err != nil {
		t.Fatalf("TokenForRepo() second error = %v", err)
	}
	if firstToken == secondToken {
		t.Fatalf("expected pre-refresh to mint a new token, got %q", secondToken)
	}
	if tokenRequests != 2 {
		t.Fatalf("token requests = %d, want 2", tokenRequests)
	}
}

func TestAppTokenSource_ClassifiesGitHubErrors(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		wantErr    error
	}{
		{name: "not found", statusCode: http.StatusNotFound, wantErr: core.ErrNotFound},
		{name: "rate limited", statusCode: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "60"}, wantErr: core.ErrRateLimited},
		{name: "unavailable", statusCode: http.StatusBadGateway, wantErr: core.ErrUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for key, value := range tc.headers {
					w.Header().Set(key, value)
				}
				http.Error(w, tc.name, tc.statusCode)
			}))
			defer server.Close()

			source, err := github.NewAppTokenSource(github.AppTokenSourceConfig{
				AppID:      123,
				PrivateKey: privateKey,
				BaseURL:    server.URL,
				Client:     server.Client(),
			})
			if err != nil {
				t.Fatalf("NewAppTokenSource() error = %v", err)
			}

			_, err = source.TokenForRepo(context.Background(), "acme", "widgets")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("TokenForRepo() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestAppTokenSource_TokenForRepoUsesRedisSharedCache(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run() error = %v", err)
	}
	defer redisServer.Close()

	redisClient := goredis.NewClient(&goredis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() {
		_ = redisClient.Close()
	})

	installationLookups := 0
	tokenRequests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/widgets/installation":
			installationLookups++
			_, _ = w.Write([]byte(`{"id":987}`))
		case "/app/installations/987/access_tokens":
			tokenRequests++
			_, _ = w.Write([]byte(`{"token":"inst-token","expires_at":"` + now.Add(10*time.Minute).Format(time.RFC3339) + `"}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cache := github.NewRedisAppTokenCache(github.RedisAppTokenCacheConfig{Client: redisClient})
	first, err := github.NewAppTokenSource(github.AppTokenSourceConfig{
		AppID:      123,
		PrivateKey: privateKey,
		BaseURL:    server.URL,
		Client:     server.Client(),
		Cache:      cache,
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewAppTokenSource() first error = %v", err)
	}
	second, err := github.NewAppTokenSource(github.AppTokenSourceConfig{
		AppID:      123,
		PrivateKey: privateKey,
		BaseURL:    server.URL,
		Client:     server.Client(),
		Cache:      cache,
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewAppTokenSource() second error = %v", err)
	}

	firstToken, err := first.TokenForRepo(context.Background(), "acme", "widgets")
	if err != nil {
		t.Fatalf("TokenForRepo() first error = %v", err)
	}
	secondToken, err := second.TokenForRepo(context.Background(), "acme", "widgets")
	if err != nil {
		t.Fatalf("TokenForRepo() second error = %v", err)
	}
	if firstToken != secondToken {
		t.Fatalf("tokens = %q/%q, want shared cached token", firstToken, secondToken)
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
