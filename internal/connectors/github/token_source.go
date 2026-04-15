package github

import (
	"context"
	"fmt"

	"github.com/evalops/asb/internal/core"
)

func FallbackTokenSource(primary RepoTokenSource, fallback RepoTokenSource) RepoTokenSource {
	if primary == nil {
		return fallback
	}
	if fallback == nil {
		return primary
	}
	return fallbackTokenSource{
		primary:  primary,
		fallback: fallback,
	}
}

type fallbackTokenSource struct {
	primary  RepoTokenSource
	fallback RepoTokenSource
}

func (s fallbackTokenSource) TokenForRepo(ctx context.Context, owner string, repo string, operation string) (string, error) {
	token, err := s.primary.TokenForRepo(ctx, owner, repo, operation)
	if err == nil {
		return token, nil
	}

	fallbackToken, fallbackErr := s.fallback.TokenForRepo(ctx, owner, repo, operation)
	if fallbackErr != nil {
		return "", fmt.Errorf("%w: primary token source failed: %v; fallback token source failed: %v", core.ErrUnauthorized, err, fallbackErr)
	}
	return fallbackToken, nil
}
