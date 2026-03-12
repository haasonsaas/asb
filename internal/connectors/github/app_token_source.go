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

	"github.com/golang-jwt/jwt/v5"
	"github.com/haasonsaas/asb/internal/core"
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
		permissions:       cfg.Permissions,
		now:               cfg.Now,
		repoInstallations: make(map[string]int64),
		installationCache: make(map[int64]cachedInstallationToken),
	}, nil
}

func (s *AppTokenSource) TokenForRepo(ctx context.Context, owner string, repo string) (string, error) {
	repoKey := owner + "/" + repo

	s.mu.Lock()
	installationID, ok := s.repoInstallations[repoKey]
	if ok {
		if cached, ok := s.installationCache[installationID]; ok && cached.expiresAt.After(s.now().Add(1*time.Minute)) {
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

	token, expiresAt, err := s.createInstallationToken(ctx, installationID, repo, appToken)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.installationCache[installationID] = cachedInstallationToken{
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
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, err
	}
	if response.StatusCode >= 400 {
		return 0, fmt.Errorf("%w: lookup GitHub installation returned %d: %s", core.ErrForbidden, response.StatusCode, string(body))
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
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", time.Time{}, err
	}
	if response.StatusCode >= 400 {
		return "", time.Time{}, fmt.Errorf("%w: create GitHub installation token returned %d: %s", core.ErrForbidden, response.StatusCode, string(body))
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
