package github_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/evalops/asb/internal/connectors/github"
	"github.com/evalops/asb/internal/core"
)

func TestHTTPExecutor_ExecutePullRequestFiles(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("authorization = %q, want bearer token", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/repos/acme/widgets/pulls/142/files" {
			t.Fatalf("path = %q, want pull request files path", r.URL.Path)
		}
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Fatalf("per_page = %q, want 100 clamp", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"files":[{"filename":"main.go"}]}`))
	}))
	defer server.Close()

	executor := github.NewHTTPExecutor(github.ExecutorConfig{
		BaseURL:     server.URL,
		Client:      server.Client(),
		TokenSource: github.StaticTokenSource("test-token"),
	})
	payload, err := executor.Execute(context.Background(), &core.Artifact{
		Metadata: map[string]string{
			"resource_ref": "github:repo:acme/widgets",
		},
	}, "pull_request_files", map[string]any{
		"pull_number": 142,
		"per_page":    1000,
		"page":        1,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if string(payload) != `{"files":[{"filename":"main.go"}]}` {
		t.Fatalf("payload = %s, want expected github json", string(payload))
	}
}

func TestHTTPExecutor_ClassifiesGitHubAPIErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		wantErr    error
	}{
		{name: "not found", statusCode: http.StatusNotFound, wantErr: core.ErrNotFound},
		{name: "permission denied", statusCode: http.StatusForbidden, wantErr: core.ErrForbidden},
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

			executor := github.NewHTTPExecutor(github.ExecutorConfig{
				BaseURL:     server.URL,
				Client:      server.Client(),
				TokenSource: github.StaticTokenSource("test-token"),
			})
			_, err := executor.Execute(context.Background(), &core.Artifact{
				Metadata: map[string]string{
					"resource_ref": "github:repo:acme/widgets",
				},
			}, "repository_metadata", nil)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Execute() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
