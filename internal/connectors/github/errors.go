package github

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/evalops/asb/internal/core"
)

func classifyGitHubAPIError(response *http.Response, body []byte, action string) error {
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = http.StatusText(response.StatusCode)
	}

	switch {
	case response.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w: %s returned %d: %s", core.ErrUnauthorized, action, response.StatusCode, message)
	case isGitHubRateLimitResponse(response):
		return fmt.Errorf("%w: %s returned %d: %s", core.ErrRateLimited, action, response.StatusCode, message)
	case response.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: %s returned %d: %s", core.ErrNotFound, action, response.StatusCode, message)
	case response.StatusCode >= http.StatusInternalServerError:
		return fmt.Errorf("%w: %s returned %d: %s", core.ErrUnavailable, action, response.StatusCode, message)
	default:
		return fmt.Errorf("%w: %s returned %d: %s", core.ErrForbidden, action, response.StatusCode, message)
	}
}

func isGitHubRateLimitResponse(response *http.Response) bool {
	switch response.StatusCode {
	case http.StatusTooManyRequests:
		return true
	case http.StatusForbidden:
		return response.Header.Get("Retry-After") != "" || response.Header.Get("X-RateLimit-Remaining") == "0"
	default:
		return false
	}
}
