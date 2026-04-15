package vaultdb_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/evalops/asb/internal/connectors/vaultdb"
	"github.com/evalops/asb/internal/core"
)

func TestConnector_IssueAndRevokeDynamicCredentials(t *testing.T) {
	t.Parallel()

	client := &fakeVaultClient{
		lease: &vaultdb.LeaseCredentials{
			Username:      "v-token-user",
			Password:      "secret:/?#[]@",
			LeaseID:       "database/creds/analytics_ro/123",
			LeaseDuration: 10 * time.Minute,
		},
	}
	connector, err := vaultdb.NewConnector(vaultdb.Config{
		Client: client,
		RoleDSNs: map[string]string{
			"analytics_ro": "postgres://{{username}}:{{password}}@db.internal:5432/analytics?sslmode=require",
		},
	})
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}

	issued, err := connector.Issue(context.Background(), core.IssueRequest{
		Session: &core.Session{ID: "sess_db", TenantID: "t_acme"},
		Grant: &core.Grant{
			ID:           "gr_db",
			DeliveryMode: core.DeliveryModeWrappedSecret,
			ExpiresAt:    time.Date(2026, 3, 12, 20, 10, 0, 0, time.UTC),
		},
		Resource: core.ResourceDescriptor{
			Kind: core.ResourceKindDBRole,
			Name: "analytics_ro",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if issued.Kind != core.ArtifactKindWrappedSecret {
		t.Fatalf("Kind = %q, want %q", issued.Kind, core.ArtifactKindWrappedSecret)
	}
	if issued.SecretData["dsn"] == "" || issued.Metadata["lease_id"] == "" {
		t.Fatalf("issued artifact = %#v, want dsn and lease id", issued)
	}
	if strings.Contains(issued.SecretData["dsn"], "secret:/?#[]@") {
		t.Fatalf("dsn = %q, want escaped credentials", issued.SecretData["dsn"])
	}

	if err := connector.Revoke(context.Background(), core.RevokeRequest{
		Session: &core.Session{ID: "sess_db", TenantID: "t_acme"},
		Grant:   &core.Grant{ID: "gr_db"},
		Artifact: &core.Artifact{
			ID: "art_db",
			Metadata: map[string]string{
				"lease_id": "database/creds/analytics_ro/123",
			},
		},
		Reason: "run_cancelled",
	}); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if client.revokedLeaseID != "database/creds/analytics_ro/123" {
		t.Fatalf("revoked lease = %q, want expected lease", client.revokedLeaseID)
	}
}

func TestNewConnectorRejectsUnsafeDSNTemplates(t *testing.T) {
	t.Parallel()

	_, err := vaultdb.NewConnector(vaultdb.Config{
		RoleDSNs: map[string]string{
			"analytics_ro": "postgres://db.internal:5432/analytics",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "placeholders") {
		t.Fatalf("NewConnector() error = %v, want placeholder validation error", err)
	}
}

func TestNewConnectorRejectsRolesOutsideAllowedSuffixes(t *testing.T) {
	t.Parallel()

	_, err := vaultdb.NewConnector(vaultdb.Config{
		AllowedRoleSuffixes: []string{"_ro"},
		RoleDSNs: map[string]string{
			"analytics_readonly": "postgres://{{username}}:{{password}}@db.internal/app",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "allowed suffixes") {
		t.Fatalf("NewConnector() error = %v, want allowed suffix validation error", err)
	}
}

func TestConnectorHonorsConfiguredRoleSuffixes(t *testing.T) {
	t.Parallel()

	connector, err := vaultdb.NewConnector(vaultdb.Config{
		AllowedRoleSuffixes: []string{"_readonly"},
		Client: &fakeVaultClient{
			lease: &vaultdb.LeaseCredentials{
				Username:      "dyn-user",
				Password:      "dyn-pass",
				LeaseID:       "lease-1",
				LeaseDuration: time.Minute,
			},
		},
		RoleDSNs: map[string]string{
			"analytics_readonly": "postgres://{{username}}:{{password}}@db.internal/app",
		},
	})
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}

	if err := connector.ValidateResource(context.Background(), core.ValidateResourceRequest{
		ResourceRef: "dbrole:analytics_readonly",
	}); err != nil {
		t.Fatalf("ValidateResource() error = %v", err)
	}

	if _, err := connector.Issue(context.Background(), core.IssueRequest{
		Session: &core.Session{ID: "sess_db", TenantID: "t_acme"},
		Grant: &core.Grant{
			ID:           "gr_db",
			DeliveryMode: core.DeliveryModeWrappedSecret,
		},
		Resource: core.ResourceDescriptor{
			Kind: core.ResourceKindDBRole,
			Name: "analytics_readwrite",
		},
	}); err == nil || !strings.Contains(err.Error(), "allowed suffixes") {
		t.Fatalf("Issue() error = %v, want suffix validation error", err)
	}
}

func TestConnectorIssueEscapesUserinfoWithPercentEncoding(t *testing.T) {
	t.Parallel()

	client := &fakeVaultClient{
		lease: &vaultdb.LeaseCredentials{
			Username:      "vault user",
			Password:      "vault secret",
			LeaseID:       "database/creds/analytics_ro/spacey",
			LeaseDuration: 10 * time.Minute,
		},
	}
	connector, err := vaultdb.NewConnector(vaultdb.Config{
		Client: client,
		RoleDSNs: map[string]string{
			"analytics_ro": "postgres://{{username}}:{{password}}@db.internal:5432/analytics",
		},
	})
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}

	issued, err := connector.Issue(context.Background(), core.IssueRequest{
		Session: &core.Session{ID: "sess_db", TenantID: "t_acme"},
		Grant: &core.Grant{
			ID:           "gr_db",
			DeliveryMode: core.DeliveryModeWrappedSecret,
		},
		Resource: core.ResourceDescriptor{
			Kind: core.ResourceKindDBRole,
			Name: "analytics_ro",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if strings.Contains(issued.SecretData["dsn"], "+") {
		t.Fatalf("dsn = %q, want spaces percent-encoded in userinfo", issued.SecretData["dsn"])
	}

	parsed, err := url.Parse(issued.SecretData["dsn"])
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	password, ok := parsed.User.Password()
	if !ok {
		t.Fatalf("parsed dsn = %q, want password present", issued.SecretData["dsn"])
	}
	if parsed.User.Username() != client.lease.Username || password != client.lease.Password {
		t.Fatalf("parsed credentials = %q/%q, want %q/%q", parsed.User.Username(), password, client.lease.Username, client.lease.Password)
	}
}

type fakeVaultClient struct {
	lease          *vaultdb.LeaseCredentials
	revokedLeaseID string
}

func (f *fakeVaultClient) GenerateCredentials(context.Context, string) (*vaultdb.LeaseCredentials, error) {
	return f.lease, nil
}

func (f *fakeVaultClient) RevokeLease(_ context.Context, leaseID string) error {
	f.revokedLeaseID = leaseID
	return nil
}
