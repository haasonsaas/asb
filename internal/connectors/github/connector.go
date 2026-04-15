package github

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/evalops/asb/internal/core"
)

type Config struct {
	AllowedOperations []string
	Budget            core.ProxyBudget
}

type Connector struct {
	allowedOperations []string
	budget            core.ProxyBudget
}

func NewConnector(cfg Config) *Connector {
	operations := normalizeOperations(cfg.AllowedOperations)
	if len(operations) == 0 {
		operations = append([]string(nil), defaultOperations...)
	}
	budget := cfg.Budget
	if budget.MaxConcurrent == 0 {
		budget.MaxConcurrent = 8
	}
	if budget.MaxRequests == 0 {
		budget.MaxRequests = 100
	}
	if budget.MaxBytes == 0 {
		budget.MaxBytes = 25 * 1024 * 1024
	}
	return &Connector{
		allowedOperations: operations,
		budget:            budget,
	}
}

func (c *Connector) Kind() string {
	return "github"
}

func (c *Connector) ValidateResource(_ context.Context, req core.ValidateResourceRequest) error {
	resource, err := core.ParseResource(req.ResourceRef)
	if err != nil {
		return err
	}
	if resource.Kind != core.ResourceKindGitHubRepo {
		return fmt.Errorf("%w: github connector only supports github repos", core.ErrInvalidRequest)
	}

	parts := strings.Split(resource.Name, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("%w: github repo must be owner/repo", core.ErrInvalidRequest)
	}
	return nil
}

func (c *Connector) Issue(_ context.Context, req core.IssueRequest) (*core.IssuedArtifact, error) {
	if req.Grant == nil || req.Session == nil {
		return nil, fmt.Errorf("%w: session and grant are required", core.ErrInvalidRequest)
	}
	if req.Grant.DeliveryMode != core.DeliveryModeProxy {
		return nil, fmt.Errorf("%w: github connector only supports proxy delivery in v1", core.ErrInvalidRequest)
	}
	if req.Resource.Kind != core.ResourceKindGitHubRepo {
		return nil, fmt.Errorf("%w: github connector requires github repo resource", core.ErrInvalidRequest)
	}

	handle := "ph_" + req.Grant.ID
	return &core.IssuedArtifact{
		Kind: core.ArtifactKindProxyHandle,
		Metadata: map[string]string{
			"handle":         handle,
			"resource_ref":   "github:repo:" + req.Resource.Name,
			"operations":     strings.Join(c.allowedOperations, ","),
			"max_concurrent": strconv.Itoa(c.budget.MaxConcurrent),
			"max_requests":   strconv.Itoa(c.budget.MaxRequests),
			"max_bytes":      strconv.FormatInt(c.budget.MaxBytes, 10),
			"connector_kind": c.Kind(),
			"session_id":     req.Session.ID,
			"grant_id":       req.Grant.ID,
		},
		ExpiresAt: req.Grant.ExpiresAt,
	}, nil
}

func (c *Connector) Revoke(context.Context, core.RevokeRequest) error {
	return nil
}
