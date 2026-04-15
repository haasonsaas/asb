package vaultdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/evalops/asb/internal/core"
	"github.com/evalops/service-runtime/resilience"
)

type HTTPClientConfig struct {
	BaseURL     string
	Token       string
	Namespace   string
	Client      *http.Client
	RevokeRetry resilience.RetryConfig
}

type HTTPClient struct {
	baseURL     string
	token       string
	namespace   string
	client      *http.Client
	revokeRetry resilience.RetryConfig
}

func NewHTTPClient(cfg HTTPClientConfig) *HTTPClient {
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	revokeRetry := cfg.RevokeRetry
	if revokeRetry.MaxAttempts == 0 {
		revokeRetry.MaxAttempts = 4
	}
	if revokeRetry.InitialDelay == 0 {
		revokeRetry.InitialDelay = 100 * time.Millisecond
	}
	if revokeRetry.MaxDelay == 0 {
		revokeRetry.MaxDelay = time.Second
	}
	return &HTTPClient{
		baseURL:     strings.TrimRight(cfg.BaseURL, "/"),
		token:       cfg.Token,
		namespace:   cfg.Namespace,
		client:      client,
		revokeRetry: revokeRetry,
	}
}

func (c *HTTPClient) GenerateCredentials(ctx context.Context, role string) (*LeaseCredentials, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/database/creds/"+role, nil)
	if err != nil {
		return nil, err
	}
	c.applyHeaders(request)

	response, err := c.client.Do(request)
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
		return nil, fmt.Errorf("%w: vault generate credentials returned %d: %s", core.ErrForbidden, response.StatusCode, string(body))
	}

	var payload struct {
		LeaseID       string `json:"lease_id"`
		LeaseDuration int64  `json:"lease_duration"`
		Data          struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return &LeaseCredentials{
		Username:      payload.Data.Username,
		Password:      payload.Data.Password,
		LeaseID:       payload.LeaseID,
		LeaseDuration: time.Duration(payload.LeaseDuration) * time.Second,
	}, nil
}

func (c *HTTPClient) RevokeLease(ctx context.Context, leaseID string) error {
	return resilience.Retry(ctx, c.revokeRetry, func(ctx context.Context) error {
		return c.revokeLeaseOnce(ctx, leaseID)
	})
}

func (c *HTTPClient) revokeLeaseOnce(ctx context.Context, leaseID string) error {
	body, err := json.Marshal(map[string]string{"lease_id": leaseID})
	if err != nil {
		return resilience.Permanent(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/sys/leases/revoke", bytes.NewReader(body))
	if err != nil {
		return resilience.Permanent(err)
	}
	c.applyHeaders(request)
	request.Header.Set("Content-Type", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		wrapped := fmt.Errorf("%w: vault revoke lease returned %d: %s", core.ErrForbidden, response.StatusCode, string(payload))
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
			return wrapped
		}
		return resilience.Permanent(wrapped)
	}
	return nil
}

func (c *HTTPClient) applyHeaders(request *http.Request) {
	request.Header.Set("X-Vault-Token", c.token)
	if c.namespace != "" {
		request.Header.Set("X-Vault-Namespace", c.namespace)
	}
}
