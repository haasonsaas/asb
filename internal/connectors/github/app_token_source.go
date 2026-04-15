package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/evalops/asb/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

type AppTokenSourceConfig struct {
	AppID       int64
	PrivateKey  *rsa.PrivateKey
	BaseURL     string
	Client      *http.Client
	Permissions map[string]string
	Now         func() time.Time
}

type AppTokenSource struct {
	appID       int64
	privateKey  *rsa.PrivateKey
	baseURL     string
	client      *http.Client
	permissions map[string]string
	now         func() time.Time

	mu                sync.Mutex
	repoInstallations map[string]int64
	installationCache map[installationTokenCacheKey]cachedInstallationToken
}

type cachedInstallationToken struct {
	token     string
	expiresAt time.Time
}

type installationTokenCacheKey struct {
	installationID    int64
	permissionScopeID string
}

func NewAppTokenSource(cfg AppTokenSourceConfig) (*AppTokenSource, error) {
	if cfg.AppID == 0 || cfg.PrivateKey == nil {
		return nil, fmt.Errorf("%w: app id and private key are required", core.ErrInvalidRequest)
	}
	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.github.com"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if len(cfg.Permissions) == 0 {
		cfg.Permissions = map[string]string{
			"contents":      "read",
			"issues":        "read",
			"pull_requests": "read",
		}
	}

	return &AppTokenSource{
		appID:             cfg.AppID,
		privateKey:        cfg.PrivateKey,
		baseURL:           strings.TrimRight(cfg.BaseURL, "/"),
		client:            cfg.Client,
		permissions:       cfg.Permissions,
		now:               cfg.Now,
		repoInstallations: make(map[string]int64),
		installationCache: make(map[installationTokenCacheKey]cachedInstallationToken),
	}, nil
}

func (s *AppTokenSource) TokenForRepo(ctx context.Context, owner string, repo string, operation string) (string, error) {
	repoKey := owner + "/" + repo
	permissions := s.permissionsForOperation(operation)
	permissionScopeID := permissionScopeKey(permissions)

	s.mu.Lock()
	installationID, ok := s.repoInstallations[repoKey]
	if ok {
		cacheKey := installationTokenCacheKey{installationID: installationID, permissionScopeID: permissionScopeID}
		if cached, ok := s.installationCache[cacheKey]; ok && cached.expiresAt.After(s.now().Add(5*time.Minute)) {
			token := cached.token
			s.mu.Unlock()
			return token, nil
		}
	}
	s.mu.Unlock()

	appToken, err := s.appJWT()
	if err != nil {
		return "", err
	}

	if !ok {
		installationID, err = s.lookupInstallationID(ctx, owner, repo, appToken)
		if err != nil {
			return "", err
		}
		s.mu.Lock()
		s.repoInstallations[repoKey] = installationID
		s.mu.Unlock()
	}

	token, expiresAt, err := s.createInstallationToken(ctx, installationID, repo, permissions, appToken)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.installationCache[installationTokenCacheKey{installationID: installationID, permissionScopeID: permissionScopeID}] = cachedInstallationToken{
		token:     token,
		expiresAt: expiresAt,
	}
	s.mu.Unlock()
	return token, nil
}

func (s *AppTokenSource) appJWT() (string, error) {
	now := s.now()
	claims := jwt.RegisteredClaims{
		Issuer:    strconv.FormatInt(s.appID, 10),
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("%w: sign GitHub App JWT: %v", core.ErrUnauthorized, err)
	}
	return signed, nil
}

func (s *AppTokenSource) lookupInstallationID(ctx context.Context, owner string, repo string, appToken string) (int64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/%s/installation", s.baseURL, owner, repo), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+appToken)
	request.Header.Set("Accept", "application/vnd.github+json")

	response, err := s.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, err
	}
	if response.StatusCode >= 400 {
		return 0, classifyGitHubAPIError(response, body, "lookup GitHub installation")
	}
	var payload struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, err
	}
	return payload.ID, nil
}

func (s *AppTokenSource) createInstallationToken(ctx context.Context, installationID int64, repo string, permissions map[string]string, appToken string) (string, time.Time, error) {
	requestBody, err := json.Marshal(map[string]any{
		"repositories": []string{repo},
		"permissions":  permissions,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/app/installations/%d/access_tokens", s.baseURL, installationID), bytes.NewReader(requestBody))
	if err != nil {
		return "", time.Time{}, err
	}
	request.Header.Set("Authorization", "Bearer "+appToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Content-Type", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", time.Time{}, err
	}
	if response.StatusCode >= 400 {
		return "", time.Time{}, classifyGitHubAPIError(response, body, "create GitHub installation token")
	}
	var payload struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", time.Time{}, err
	}
	return payload.Token, payload.ExpiresAt, nil
}

func (s *AppTokenSource) permissionsForOperation(operation string) map[string]string {
	if permissions, ok := operationPermissions[operation]; ok {
		return clonePermissions(permissions)
	}
	return clonePermissions(s.permissions)
}

var operationPermissions = map[string]map[string]string{
	"pull_request_metadata":       {"pull_requests": "read"},
	"pull_request_files":          {"pull_requests": "read"},
	"repository_metadata":         {"contents": "read"},
	"repository_issues":           {"issues": "read"},
	"create_issue":                {"issues": "write"},
	"create_pull_request_comment": {"issues": "write"},
	"create_check_run":            {"checks": "write"},
}

func clonePermissions(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func permissionScopeKey(permissions map[string]string) string {
	if len(permissions) == 0 {
		return "default"
	}
	keys := make([]string, 0, len(permissions))
	for key := range permissions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+permissions[key])
	}
	return strings.Join(parts, ",")
}
