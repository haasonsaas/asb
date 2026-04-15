package github

import (
	"errors"
	"net/http"
	"testing"

	"github.com/evalops/asb/internal/core"
)

func TestClassifyGitHubAPIError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		wantErr    error
	}{
		{name: "unauthorized", statusCode: http.StatusUnauthorized, wantErr: core.ErrUnauthorized},
		{name: "not found stays not found when rate limit headers are present", statusCode: http.StatusNotFound, headers: map[string]string{"X-RateLimit-Remaining": "0"}, wantErr: core.ErrNotFound},
		{name: "forbidden with retry after is rate limited", statusCode: http.StatusForbidden, headers: map[string]string{"Retry-After": "60"}, wantErr: core.ErrRateLimited},
		{name: "too many requests is rate limited", statusCode: http.StatusTooManyRequests, wantErr: core.ErrRateLimited},
		{name: "service unavailable with retry after stays unavailable", statusCode: http.StatusServiceUnavailable, headers: map[string]string{"Retry-After": "60"}, wantErr: core.ErrUnavailable},
		{name: "forbidden default", statusCode: http.StatusForbidden, wantErr: core.ErrForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			response := &http.Response{
				StatusCode: tc.statusCode,
				Header:     make(http.Header),
			}
			for key, value := range tc.headers {
				response.Header.Set(key, value)
			}

			err := classifyGitHubAPIError(response, []byte("test message"), "github api request")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("classifyGitHubAPIError() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
