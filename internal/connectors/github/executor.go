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
	requestSpec, err := e.buildRequest(operation, owner, repo, params)
	if err != nil {
		return nil, err
	}
	token, err := e.tokenSource.TokenForRepo(ctx, owner, repo, operation)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, requestSpec.method, requestSpec.url, bytes.NewReader(requestSpec.body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	if len(requestSpec.body) > 0 {
		request.Header.Set("Content-Type", "application/json")
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

type requestSpec struct {
	method string
	url    string
	body   []byte
}

func (e *HTTPExecutor) buildRequest(operation string, owner string, repo string, params map[string]any) (requestSpec, error) {
	u, err := url.Parse(e.baseURL)
	if err != nil {
		return requestSpec{}, err
	}

	switch operation {
	case operationPullRequestMetadata:
		u.Path = fmt.Sprintf("%s/repos/%s/%s/pulls/%d", u.Path, owner, repo, intFromAny(params["pull_number"]))
	case operationPullRequestFiles:
		u.Path = fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files", u.Path, owner, repo, intFromAny(params["pull_number"]))
		q := u.Query()
		q.Set("page", strconv.Itoa(max(intFromAny(params["page"]), 1)))
		q.Set("per_page", strconv.Itoa(min(max(intFromAny(params["per_page"]), 1), 100)))
		u.RawQuery = q.Encode()
	case operationRepositoryMetadata:
		u.Path = fmt.Sprintf("%s/repos/%s/%s", u.Path, owner, repo)
	case operationRepositoryIssues:
		u.Path = fmt.Sprintf("%s/repos/%s/%s/issues", u.Path, owner, repo)
		q := u.Query()
		q.Set("page", strconv.Itoa(max(intFromAny(params["page"]), 1)))
		q.Set("per_page", strconv.Itoa(min(max(intFromAny(params["per_page"]), 1), 100)))
		u.RawQuery = q.Encode()
	case operationCreateIssue:
		u.Path = fmt.Sprintf("%s/repos/%s/%s/issues", u.Path, owner, repo)
		body, err := marshalRequestBody(map[string]any{
			"title":     params["title"],
			"body":      params["body"],
			"assignees": params["assignees"],
			"labels":    params["labels"],
		})
		if err != nil {
			return requestSpec{}, err
		}
		return requestSpec{method: http.MethodPost, url: u.String(), body: body}, nil
	case operationCreatePullRequestComment:
		u.Path = fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", u.Path, owner, repo, intFromAny(params["pull_number"]))
		body, err := marshalRequestBody(map[string]any{
			"body": params["body"],
		})
		if err != nil {
			return requestSpec{}, err
		}
		return requestSpec{method: http.MethodPost, url: u.String(), body: body}, nil
	case operationCreateCheckRun:
		u.Path = fmt.Sprintf("%s/repos/%s/%s/check-runs", u.Path, owner, repo)
		body, err := marshalRequestBody(map[string]any{
			"name":         params["name"],
			"head_sha":     params["head_sha"],
			"details_url":  params["details_url"],
			"external_id":  params["external_id"],
			"status":       params["status"],
			"conclusion":   params["conclusion"],
			"started_at":   params["started_at"],
			"completed_at": params["completed_at"],
			"output":       params["output"],
		})
		if err != nil {
			return requestSpec{}, err
		}
		return requestSpec{method: http.MethodPost, url: u.String(), body: body}, nil
	default:
		return requestSpec{}, fmt.Errorf("%w: github operation %q is not allowlisted", core.ErrForbidden, operation)
	}
	return requestSpec{method: http.MethodGet, url: u.String()}, nil
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

func marshalRequestBody(payload map[string]any) ([]byte, error) {
	filtered := make(map[string]any, len(payload))
	for key, value := range payload {
		if value == nil {
			continue
		}
		filtered[key] = value
	}
	if len(filtered) == 0 {
		return nil, nil
	}
	return json.Marshal(filtered)
}
