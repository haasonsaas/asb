package browser

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/andybalholm/cascadia"
	"github.com/evalops/asb/internal/core"
)

type Credential struct {
	Username string
	Password string
	OTP      string
}

type SelectorMap struct {
	Username string
	Password string
	OTP      string
}

type CredentialStore interface {
	Get(ctx context.Context, origin string) (*Credential, error)
}

type Config struct {
	Credentials            CredentialStore
	SelectorMaps           map[string]SelectorMap
	AllowInsecureLocalhost bool
}

type Connector struct {
	credentials            CredentialStore
	selectorMaps           map[string]SelectorMap
	allowInsecureLocalhost bool
}

func NewConnector(cfg Config) (*Connector, error) {
	if cfg.Credentials == nil {
		return nil, fmt.Errorf("%w: browser credentials are required", core.ErrInvalidRequest)
	}
	for origin, selectorMap := range cfg.SelectorMaps {
		if err := validateOrigin(origin, cfg.AllowInsecureLocalhost); err != nil {
			return nil, err
		}
		if err := validateSelectorMap(selectorMap); err != nil {
			return nil, fmt.Errorf("validate selector map for %q: %w", origin, err)
		}
	}
	return &Connector{
		credentials:            cfg.Credentials,
		selectorMaps:           cfg.SelectorMaps,
		allowInsecureLocalhost: cfg.AllowInsecureLocalhost,
	}, nil
}

func validateOrigin(origin string, allowInsecureLocalhost bool) error {
	if strings.TrimSpace(origin) == "" {
		return fmt.Errorf("%w: browser origin is required", core.ErrInvalidRequest)
	}
	parsed, err := url.ParseRequestURI(origin)
	if err != nil {
		return fmt.Errorf("%w: invalid browser origin %q", core.ErrInvalidRequest, origin)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: invalid browser origin %q", core.ErrInvalidRequest, origin)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: browser origin %q must not include credentials, query, or fragment", core.ErrInvalidRequest, origin)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("%w: browser origin %q must not include a path", core.ErrInvalidRequest, origin)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecureLocalhost && parsed.Hostname() == "localhost" {
			return nil
		}
	}
	return fmt.Errorf("%w: browser origin %q must use https", core.ErrInvalidRequest, origin)
}

func validateSelectorMap(selectorMap SelectorMap) error {
	if err := validateSelector("username", selectorMap.Username, true); err != nil {
		return err
	}
	if err := validateSelector("password", selectorMap.Password, true); err != nil {
		return err
	}
	if err := validateSelector("otp", selectorMap.OTP, false); err != nil {
		return err
	}
	return nil
}

func validateSelector(name string, selector string, required bool) error {
	trimmed := strings.TrimSpace(selector)
	if trimmed == "" {
		if required {
			return fmt.Errorf("%w: browser %s selector is required", core.ErrInvalidRequest, name)
		}
		return nil
	}
	if _, err := cascadia.Parse(trimmed); err != nil {
		return fmt.Errorf("%w: invalid browser %s selector %q: %v", core.ErrInvalidRequest, name, trimmed, err)
	}
	return nil
}

func StaticCredentialStore(entries map[string]Credential) CredentialStore {
	return staticCredentialStore(entries)
}

func (c *Connector) Kind() string {
	return "browser"
}

func (c *Connector) ValidateResource(_ context.Context, req core.ValidateResourceRequest) error {
	resource, err := core.ParseResource(req.ResourceRef)
	if err != nil {
		return err
	}
	if resource.Kind != core.ResourceKindBrowserOrigin {
		return fmt.Errorf("%w: browser connector only supports browser origins", core.ErrInvalidRequest)
	}
	if err := validateOrigin(resource.Origin, c.allowInsecureLocalhost); err != nil {
		return err
	}
	selectorMap, ok := c.selectorMaps[resource.Origin]
	if !ok {
		return fmt.Errorf("%w: no selector map configured for %q", core.ErrNotFound, resource.Origin)
	}
	if err := validateSelectorMap(selectorMap); err != nil {
		return err
	}
	return nil
}

func (c *Connector) Issue(ctx context.Context, req core.IssueRequest) (*core.IssuedArtifact, error) {
	if req.Session == nil || req.Grant == nil {
		return nil, fmt.Errorf("%w: session and grant are required", core.ErrInvalidRequest)
	}
	if req.Grant.DeliveryMode != core.DeliveryModeWrappedSecret {
		return nil, fmt.Errorf("%w: browser connector only supports wrapped secret delivery", core.ErrInvalidRequest)
	}
	selectorMap, ok := c.selectorMaps[req.Resource.Origin]
	if !ok {
		return nil, fmt.Errorf("%w: no selector map configured for %q", core.ErrNotFound, req.Resource.Origin)
	}
	credential, err := c.credentials.Get(ctx, req.Resource.Origin)
	if err != nil {
		return nil, err
	}

	metadata := map[string]string{
		"artifact_id":       "art_" + req.Grant.ID,
		"origin":            req.Resource.Origin,
		"selector_username": selectorMap.Username,
		"selector_password": selectorMap.Password,
	}
	if selectorMap.OTP != "" {
		metadata["selector_otp"] = selectorMap.OTP
	}

	secretData := map[string]string{
		"username": credential.Username,
		"password": credential.Password,
	}
	if credential.OTP != "" {
		secretData["otp"] = credential.OTP
	}

	return &core.IssuedArtifact{
		Kind:       core.ArtifactKindWrappedSecret,
		Metadata:   metadata,
		SecretData: secretData,
		ExpiresAt:  req.Grant.ExpiresAt,
	}, nil
}

func (c *Connector) Revoke(context.Context, core.RevokeRequest) error {
	return nil
}

type staticCredentialStore map[string]Credential

func (s staticCredentialStore) Get(_ context.Context, origin string) (*Credential, error) {
	value, ok := s[origin]
	if !ok {
		return nil, fmt.Errorf("%w: browser credential for %q", core.ErrNotFound, origin)
	}
	cp := value
	return &cp, nil
}
