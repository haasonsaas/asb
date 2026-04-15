package github_test

import (
	"context"
	"testing"
	"time"

	"github.com/evalops/asb/internal/connectors/github"
	"github.com/evalops/asb/internal/core"
)

func TestConnector_ValidateResource(t *testing.T) {
	t.Parallel()

	connector := github.NewConnector(github.Config{})
	if err := connector.ValidateResource(context.Background(), core.ValidateResourceRequest{
		TenantID:    "t_acme",
		Capability:  "repo.read",
		ResourceRef: "github:repo:acme/widgets",
	}); err != nil {
		t.Fatalf("ValidateResource() error = %v", err)
	}
}

func TestConnector_IssueReturnsAllowlistedProxyHandle(t *testing.T) {
	t.Parallel()

	connector := github.NewConnector(github.Config{
		AllowedOperations: []string{"pull_request_metadata", "pull_request_files"},
		Budget: core.ProxyBudget{
			MaxConcurrent: 8,
			MaxRequests:   100,
			MaxBytes:      25 * 1024 * 1024,
		},
	})

	issued, err := connector.Issue(context.Background(), core.IssueRequest{
		Session: &core.Session{ID: "sess_abc", TenantID: "t_acme"},
		Grant: &core.Grant{
			ID:           "gr_123",
			DeliveryMode: core.DeliveryModeProxy,
			ExpiresAt:    time.Date(2026, 3, 12, 20, 10, 0, 0, time.UTC),
		},
		Resource: core.ResourceDescriptor{
			Kind: core.ResourceKindGitHubRepo,
			Name: "acme/widgets",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if issued.Kind != core.ArtifactKindProxyHandle {
		t.Fatalf("Kind = %q, want %q", issued.Kind, core.ArtifactKindProxyHandle)
	}
	if issued.Metadata["handle"] == "" {
		t.Fatal("handle metadata is empty")
	}
	if issued.Metadata["operations"] != "pull_request_metadata,pull_request_files" {
		t.Fatalf("operations = %q, want allowlist", issued.Metadata["operations"])
	}
	if issued.Metadata["resource_ref"] != "github:repo:acme/widgets" {
		t.Fatalf("resource_ref = %q, want github repo ref", issued.Metadata["resource_ref"])
	}
}

func TestConnector_IssueAllowsConfiguredWriteOperations(t *testing.T) {
	t.Parallel()

	connector := github.NewConnector(github.Config{
		AllowedOperations: []string{"create_issue", "create_pull_request_comment", "create_check_run", "unknown"},
	})

	issued, err := connector.Issue(context.Background(), core.IssueRequest{
		Session: &core.Session{ID: "sess_write", TenantID: "t_acme"},
		Grant: &core.Grant{
			ID:           "gr_write",
			DeliveryMode: core.DeliveryModeProxy,
			ExpiresAt:    time.Date(2026, 3, 12, 20, 10, 0, 0, time.UTC),
		},
		Resource: core.ResourceDescriptor{
			Kind: core.ResourceKindGitHubRepo,
			Name: "acme/widgets",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if got := issued.Metadata["operations"]; got != "create_issue,create_pull_request_comment,create_check_run" {
		t.Fatalf("operations = %q, want configured write allowlist", got)
	}
}
