package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/evalops/asb/internal/core"
)

type RepoTokenSource interface {
	TokenForRepo(ctx context.Context, owner string, repo string, operation string) (string, error)
}

type ExecutorConfig struct {
	BaseURL     string
	Client      *http.Client
	TokenSource RepoTokenSource
}

type HTTPExecutor struct {
	baseURL     string
	client      *http.Client
	tokenSource RepoTokenSource
}

func NewHTTPExecutor(cfg ExecutorConfig) *HTTPExecutor {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPExecutor{
		baseURL:     strings.TrimRight(baseURL, "/"),
		client:      client,
		tokenSource: cfg.TokenSource,
	}
}

func StaticTokenSource(token string) RepoTokenSource {
	return staticTokenSource(token)
}

func (e *HTTPExecutor) Execute(ctx context.Context, artifact *core.Artifact, operation string, params map[string]any) ([]byte, error) {
	if e.tokenSource == nil {
		return nil, fmt.Errorf("%w: github token source is not configured", core.ErrInvalidRequest)
	}
	owner, repo, err := parseOwnerRepo(artifact.Metadata["resource_ref"])
	if err != nil {
		return nil, err
	}
	token, err := e.tokenSource.TokenForRepo(ctx, owner, repo, operation)
	if err != nil {
		return nil, err
	}

	request, err := e.buildRequest(ctx, token, operation, owner, repo, params)
	if err != nil {
		return nil, err
	}

	response, err := e.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, classifyGitHubAPIError(response, body, "github api request")
	}
	return body, nil
}

func (e *HTTPExecutor) buildRequest(ctx context.Context, token string, operation string, owner string, repo string, params map[string]any) (*http.Request, error) {
	u, err := url.Parse(e.baseURL)
	if err != nil {
		return nil, err
	}

	method := http.MethodGet
	var body io.Reader
	switch operation {
	case "pull_request_metadata":
		u.Path = fmt.Sprintf("%s/repos/%s/%s/pulls/%d", u.Path, owner, repo, intFromAny(params["pull_number"]))
	case "pull_request_files":
		u.Path = fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files", u.Path, owner, repo, intFromAny(params["pull_number"]))
		q := u.Query()
		q.Set("page", strconv.Itoa(max(intFromAny(params["page"]), 1)))
		q.Set("per_page", strconv.Itoa(min(max(intFromAny(params["per_page"]), 1), 100)))
		u.RawQuery = q.Encode()
	case "repository_metadata":
		u.Path = fmt.Sprintf("%s/repos/%s/%s", u.Path, owner, repo)
	case "repository_issues":
		u.Path = fmt.Sprintf("%s/repos/%s/%s/issues", u.Path, owner, repo)
		q := u.Query()
		q.Set("page", strconv.Itoa(max(intFromAny(params["page"]), 1)))
		q.Set("per_page", strconv.Itoa(min(max(intFromAny(params["per_page"]), 1), 100)))
		u.RawQuery = q.Encode()
	case "create_issue":
		method = http.MethodPost
		u.Path = fmt.Sprintf("%s/repos/%s/%s/issues", u.Path, owner, repo)
		body, err = encodeJSONBody(params)
		if err != nil {
			return nil, err
		}
	case "create_pull_request_comment":
		method = http.MethodPost
		u.Path = fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", u.Path, owner, repo, intFromAny(params["pull_number"]))
		body, err = encodeJSONBody(cloneWithoutKeys(params, "pull_number"))
		if err != nil {
			return nil, err
		}
	case "create_check_run":
		method = http.MethodPost
		u.Path = fmt.Sprintf("%s/repos/%s/%s/check-runs", u.Path, owner, repo)
		body, err = encodeJSONBody(params)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: github operation %q is not allowlisted", core.ErrForbidden, operation)
	}

	request, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if method != http.MethodGet {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func encodeJSONBody(payload map[string]any) (io.Reader, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode github request body: %v", core.ErrInvalidRequest, err)
	}
	return bytes.NewReader(body), nil
}

func cloneWithoutKeys(params map[string]any, keys ...string) map[string]any {
	if len(params) == 0 {
		return map[string]any{}
	}
	exclude := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		exclude[key] = struct{}{}
	}
	cloned := make(map[string]any, len(params))
	for key, value := range params {
		if _, skip := exclude[key]; skip {
			continue
		}
		cloned[key] = value
	}
	return cloned
}

func parseOwnerRepo(resourceRef string) (string, string, error) {
	resource, err := core.ParseResource(resourceRef)
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(resource.Name, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%w: github repo must be owner/repo", core.ErrInvalidRequest)
	}
	return parts[0], parts[1], nil
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		out, _ := strconv.Atoi(v)
		return out
	default:
		return 0
	}
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

type staticTokenSource string

func (s staticTokenSource) TokenForRepo(context.Context, string, string, string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("%w: github token is empty", core.ErrInvalidRequest)
	}
	return string(s), nil
}
