package github_test

import (
	"context"
	"errors"
	"testing"

	"github.com/evalops/asb/internal/connectors/github"
)

func TestFallbackTokenSourceUsesFallbackOnPrimaryFailure(t *testing.T) {
	t.Parallel()

	source := github.FallbackTokenSource(
		repoTokenSourceFunc(func(context.Context, string, string) (string, error) {
			return "", errors.New("app token exchange failed")
		}),
		repoTokenSourceFunc(func(context.Context, string, string) (string, error) {
			return "static-token", nil
		}),
	)

	token, err := source.TokenForRepo(context.Background(), "acme", "widgets")
	if err != nil {
		t.Fatalf("TokenForRepo() error = %v", err)
	}
	if token != "static-token" {
		t.Fatalf("token = %q, want static-token", token)
	}
}

type repoTokenSourceFunc func(context.Context, string, string) (string, error)

func (fn repoTokenSourceFunc) TokenForRepo(ctx context.Context, owner string, repo string) (string, error) {
	return fn(ctx, owner, repo)
}
