package oidc

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/evalops/asb/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

type Keyfunc func(ctx context.Context, token *jwt.Token) (any, error)

type Config struct {
	Issuer                 string
	Audience               string
	Keyfunc                Keyfunc
	AllowedSubjectPrefixes []string
}

type Verifier struct {
	issuer                 string
	audience               string
	keyfunc                Keyfunc
	allowedSubjectPrefixes []string
}

func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.Keyfunc == nil {
		return nil, fmt.Errorf("%w: issuer, audience, and keyfunc are required", core.ErrInvalidRequest)
	}
	prefixes := make([]string, 0, len(cfg.AllowedSubjectPrefixes))
	for _, prefix := range cfg.AllowedSubjectPrefixes {
		if trimmed := strings.TrimSpace(prefix); trimmed != "" {
			prefixes = append(prefixes, trimmed)
		}
	}
	return &Verifier{
		issuer:                 cfg.Issuer,
		audience:               cfg.Audience,
		keyfunc:                cfg.Keyfunc,
		allowedSubjectPrefixes: prefixes,
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, in *core.Attestation) (*core.WorkloadIdentity, error) {
	if in == nil || in.Kind != core.AttestationKindOIDCJWT || strings.TrimSpace(in.Token) == "" {
		return nil, fmt.Errorf("%w: oidc jwt attestation is required", core.ErrInvalidRequest)
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(in.Token, claims, func(token *jwt.Token) (any, error) {
		return v.keyfunc(ctx, token)
	}, jwt.WithIssuer(v.issuer), jwt.WithAudience(v.audience))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrUnauthorized, err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("%w: invalid oidc token", core.ErrUnauthorized)
	}

	subject, _ := claims["sub"].(string)
	if strings.TrimSpace(subject) == "" {
		return nil, fmt.Errorf("%w: oidc token missing subject", core.ErrUnauthorized)
	}
	if len(v.allowedSubjectPrefixes) > 0 && !hasAllowedSubjectPrefix(subject, v.allowedSubjectPrefixes) {
		return nil, fmt.Errorf("%w: unexpected oidc subject %q", core.ErrUnauthorized, subject)
	}

	issuer, _ := claims["iss"].(string)
	identity := &core.WorkloadIdentity{
		Type:       core.WorkloadIdentityTypeOIDC,
		Issuer:     issuer,
		Subject:    subject,
		Audience:   v.audience,
		Attributes: map[string]string{},
	}
	copyStringClaim(identity.Attributes, claims, "actor")
	copyStringClaim(identity.Attributes, claims, "environment")
	copyStringClaim(identity.Attributes, claims, "event_name")
	copyStringClaim(identity.Attributes, claims, "job_workflow_ref")
	copyStringClaim(identity.Attributes, claims, "ref")
	copyStringClaim(identity.Attributes, claims, "repository")
	copyStringClaim(identity.Attributes, claims, "repository_owner")
	copyStringClaim(identity.Attributes, claims, "repository_visibility")
	copyStringClaim(identity.Attributes, claims, "runner_environment")
	copyStringClaim(identity.Attributes, claims, "sha")
	copyStringClaim(identity.Attributes, claims, "workflow")
	copyNumericClaim(identity.Attributes, claims, "run_attempt")
	copyNumericClaim(identity.Attributes, claims, "run_id")
	return identity, nil
}

func hasAllowedSubjectPrefix(subject string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(subject, prefix) {
			return true
		}
	}
	return false
}

func copyStringClaim(attributes map[string]string, claims jwt.MapClaims, key string) {
	if value, ok := claims[key].(string); ok && strings.TrimSpace(value) != "" {
		attributes[key] = strings.TrimSpace(value)
	}
}

func copyNumericClaim(attributes map[string]string, claims jwt.MapClaims, key string) {
	switch value := claims[key].(type) {
	case float64:
		attributes[key] = strconv.FormatInt(int64(value), 10)
	case int64:
		attributes[key] = strconv.FormatInt(value, 10)
	case int32:
		attributes[key] = strconv.FormatInt(int64(value), 10)
	case string:
		if strings.TrimSpace(value) != "" {
			attributes[key] = strings.TrimSpace(value)
		}
	}
}
