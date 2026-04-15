package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	Cache       AppTokenCache
	Permissions map[string]string
	Now         func() time.Time
}

type AppTokenSource struct {
	appID       int64
	privateKey  *rsa.PrivateKey
	baseURL     string
	client      *http.Client
	cache       AppTokenCache
	permissions map[string]string
	now         func() time.Time

	mu                sync.Mutex
	repoInstallations map[string]int64
	installationCache map[int64]cachedInstallationToken
}

type cachedInstallationToken struct {
	token     string
	expiresAt time.Time
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
		cache:             cfg.Cache,
		permissions:       cfg.Permissions,
		now:               cfg.Now,
		repoInstallations: make(map[string]int64),
		installationCache: make(map[int64]cachedInstallationToken),
	}, nil
}

func (s *AppTokenSource) TokenForRepo(ctx context.Context, owner string, repo string) (string, error) {
	repoKey := owner + "/" + repo

	installationID, ok := s.lookupInstallationIDCache(ctx, repoKey)
	if ok {
		if cached, ok := s.lookupInstallationTokenCache(ctx, installationID); ok {
			return cached.token, nil
		}
	}

	appToken, err := s.appJWT()
	if err != nil {
		return "", err
	}

	if !ok {
		installationID, err = s.lookupInstallationID(ctx, owner, repo, appToken)
		if err != nil {
			return "", err
		}
		s.storeInstallationIDCache(ctx, repoKey, installationID)
	}

	token, expiresAt, err := s.createInstallationToken(ctx, installationID, repo, appToken)
	if err != nil {
		return "", err
	}
	s.storeInstallationTokenCache(ctx, installationID, cachedInstallationToken{
		token:     token,
		expiresAt: expiresAt,
	})
	return token, nil
}

func (s *AppTokenSource) lookupInstallationIDCache(ctx context.Context, repoKey string) (int64, bool) {
	s.mu.Lock()
	installationID, ok := s.repoInstallations[repoKey]
	s.mu.Unlock()
	if ok {
		return installationID, true
	}
	if s.cache == nil {
		return 0, false
	}
	installationID, ok, err := s.cache.GetRepoInstallation(ctx, repoKey)
	if err != nil || !ok {
		return 0, false
	}
	s.mu.Lock()
	s.repoInstallations[repoKey] = installationID
	s.mu.Unlock()
	return installationID, true
}

func (s *AppTokenSource) storeInstallationIDCache(ctx context.Context, repoKey string, installationID int64) {
	s.mu.Lock()
	s.repoInstallations[repoKey] = installationID
	s.mu.Unlock()
	if s.cache != nil {
		_ = s.cache.SetRepoInstallation(ctx, repoKey, installationID)
	}
}

func (s *AppTokenSource) lookupInstallationTokenCache(ctx context.Context, installationID int64) (cachedInstallationToken, bool) {
	s.mu.Lock()
	cached, ok := s.installationCache[installationID]
	s.mu.Unlock()
	if ok && cached.expiresAt.After(s.now().Add(5*time.Minute)) {
		return cached, true
	}
	if s.cache == nil {
		return cachedInstallationToken{}, false
	}
	cached, ok, err := s.cache.GetInstallationToken(ctx, installationID)
	if err != nil || !ok || !cached.expiresAt.After(s.now().Add(5*time.Minute)) {
		return cachedInstallationToken{}, false
	}
	s.mu.Lock()
	s.installationCache[installationID] = cached
	s.mu.Unlock()
	return cached, true
}

func (s *AppTokenSource) storeInstallationTokenCache(ctx context.Context, installationID int64, cached cachedInstallationToken) {
	s.mu.Lock()
	s.installationCache[installationID] = cached
	s.mu.Unlock()
	if s.cache != nil {
		_ = s.cache.SetInstallationToken(ctx, installationID, cached)
	}
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

func (s *AppTokenSource) createInstallationToken(ctx context.Context, installationID int64, repo string, appToken string) (string, time.Time, error) {
	requestBody, err := json.Marshal(map[string]any{
		"repositories": []string{repo},
		"permissions":  s.permissions,
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
