package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/evalops/asb/internal/connectors/github"
	"github.com/evalops/asb/internal/core"
)

func TestHTTPExecutor_ExecutePullRequestFiles(t *testing.T) {
	t.Parallel()

	tokenSource := &capturingTokenSource{token: "test-token"}
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
		TokenSource: tokenSource,
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
	if tokenSource.operation != "pull_request_files" {
		t.Fatalf("operation = %q, want pull_request_files", tokenSource.operation)
	}
}

func TestHTTPExecutor_ExecuteWriteOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		operation     string
		params        map[string]any
		wantMethod    string
		wantPath      string
		wantBodyValue map[string]any
	}{
		{
			name:       "create issue",
			operation:  "create_issue",
			params:     map[string]any{"title": "Bug report", "body": "Details"},
			wantMethod: http.MethodPost,
			wantPath:   "/repos/acme/widgets/issues",
			wantBodyValue: map[string]any{
				"title": "Bug report",
				"body":  "Details",
			},
		},
		{
			name:       "create pull request comment",
			operation:  "create_pull_request_comment",
			params:     map[string]any{"pull_number": 42, "body": "Looks good"},
			wantMethod: http.MethodPost,
			wantPath:   "/repos/acme/widgets/issues/42/comments",
			wantBodyValue: map[string]any{
				"body": "Looks good",
			},
		},
		{
			name:       "create check run",
			operation:  "create_check_run",
			params:     map[string]any{"name": "asb-check", "head_sha": "abc123", "status": "queued"},
			wantMethod: http.MethodPost,
			wantPath:   "/repos/acme/widgets/check-runs",
			wantBodyValue: map[string]any{
				"name":     "asb-check",
				"head_sha": "abc123",
				"status":   "queued",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tokenSource := &capturingTokenSource{token: "test-token"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.wantMethod {
					t.Fatalf("method = %s, want %s", r.Method, tc.wantMethod)
				}
				if r.URL.Path != tc.wantPath {
					t.Fatalf("path = %q, want %q", r.URL.Path, tc.wantPath)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				var payload map[string]any
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("unmarshal body: %v", err)
				}
				if len(payload) != len(tc.wantBodyValue) {
					t.Fatalf("payload = %#v, want %#v", payload, tc.wantBodyValue)
				}
				for key, value := range tc.wantBodyValue {
					if payload[key] != value {
						t.Fatalf("payload[%q] = %#v, want %#v", key, payload[key], value)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer server.Close()

			executor := github.NewHTTPExecutor(github.ExecutorConfig{
				BaseURL:     server.URL,
				Client:      server.Client(),
				TokenSource: tokenSource,
			})
			_, err := executor.Execute(context.Background(), &core.Artifact{
				Metadata: map[string]string{
					"resource_ref": "github:repo:acme/widgets",
				},
			}, tc.operation, tc.params)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if tokenSource.operation != tc.operation {
				t.Fatalf("operation = %q, want %q", tokenSource.operation, tc.operation)
			}
		})
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

type capturingTokenSource struct {
	token     string
	operation string
}

func (s *capturingTokenSource) TokenForRepo(_ context.Context, _ string, _ string, operation string) (string, error) {
	s.operation = operation
	return s.token, nil
}
