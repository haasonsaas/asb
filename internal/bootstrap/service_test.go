package bootstrap

import (
	"strings"
	"testing"
)

func TestNewApprovalNotifierDisabledByDefault(t *testing.T) {
	t.Setenv("ASB_NOTIFICATIONS_BASE_URL", "")
	t.Setenv("ASB_NOTIFICATIONS_RECIPIENT_ID", "")
	t.Setenv("ASB_NOTIFICATIONS_CHANNEL", "")
	t.Setenv("ASB_NOTIFICATIONS_WORKSPACE_ID", "")
	t.Setenv("ASB_NOTIFICATIONS_BEARER_TOKEN", "")
	t.Setenv("ASB_PUBLIC_BASE_URL", "")

	notifier, err := newApprovalNotifier()
	if err != nil {
		t.Fatalf("newApprovalNotifier() error = %v", err)
	}
	if notifier != nil {
		t.Fatalf("newApprovalNotifier() = %#v, want nil", notifier)
	}
}

func TestNewApprovalNotifierRequiresBaseURLWhenConfigured(t *testing.T) {
	t.Setenv("ASB_NOTIFICATIONS_BASE_URL", "")
	t.Setenv("ASB_NOTIFICATIONS_RECIPIENT_ID", "approval-queue")
	t.Setenv("ASB_NOTIFICATIONS_CHANNEL", "slack")

	notifier, err := newApprovalNotifier()
	if err == nil || !strings.Contains(err.Error(), "ASB_NOTIFICATIONS_BASE_URL") {
		t.Fatalf("newApprovalNotifier() error = %v, want base url error", err)
	}
	if notifier != nil {
		t.Fatalf("newApprovalNotifier() = %#v, want nil", notifier)
	}
}

func TestNewApprovalNotifierRequiresValidChannel(t *testing.T) {
	t.Setenv("ASB_NOTIFICATIONS_BASE_URL", "http://notifications:8080")
	t.Setenv("ASB_NOTIFICATIONS_RECIPIENT_ID", "approval-queue")
	t.Setenv("ASB_NOTIFICATIONS_CHANNEL", "sms")

	notifier, err := newApprovalNotifier()
	if err == nil || !strings.Contains(err.Error(), "ASB_NOTIFICATIONS_CHANNEL") {
		t.Fatalf("newApprovalNotifier() error = %v, want channel error", err)
	}
	if notifier != nil {
		t.Fatalf("newApprovalNotifier() = %#v, want nil", notifier)
	}
}

func TestNewApprovalNotifierConfigured(t *testing.T) {
	t.Setenv("ASB_NOTIFICATIONS_BASE_URL", "http://notifications:8080")
	t.Setenv("ASB_NOTIFICATIONS_RECIPIENT_ID", "approval-queue")
	t.Setenv("ASB_NOTIFICATIONS_CHANNEL", "slack")
	t.Setenv("ASB_NOTIFICATIONS_WORKSPACE_ID", "ws_control")
	t.Setenv("ASB_NOTIFICATIONS_BEARER_TOKEN", "secret-token")
	t.Setenv("ASB_PUBLIC_BASE_URL", "https://asb.example.com")

	notifier, err := newApprovalNotifier()
	if err != nil {
		t.Fatalf("newApprovalNotifier() error = %v", err)
	}
	if notifier == nil {
		t.Fatal("newApprovalNotifier() = nil, want configured notifier")
	}
}

func TestNewVaultDBConnectorUsesConfiguredRoleSuffixes(t *testing.T) {
	t.Setenv("ASB_VAULT_ADDR", "https://vault.internal")
	t.Setenv("ASB_VAULT_DSN_TEMPLATE", "postgres://{{username}}:{{password}}@db.internal/app")
	t.Setenv("ASB_VAULT_ROLE", "analytics_readonly")
	t.Setenv("ASB_VAULT_ALLOWED_ROLE_SUFFIXES", "_readonly,_reader")

	connector, err := newVaultDBConnector()
	if err != nil {
		t.Fatalf("newVaultDBConnector() error = %v", err)
	}
	if connector == nil {
		t.Fatal("newVaultDBConnector() = nil, want connector")
	}
}

func TestNewVaultDBConnectorFailsForInvalidTemplates(t *testing.T) {
	t.Setenv("ASB_VAULT_ADDR", "https://vault.internal")
	t.Setenv("ASB_VAULT_DSN_TEMPLATE", "postgres://db.internal/app")

	connector, err := newVaultDBConnector()
	if err == nil || !strings.Contains(err.Error(), "placeholders") {
		t.Fatalf("newVaultDBConnector() error = %v, want placeholder validation error", err)
	}
	if connector != nil {
		t.Fatalf("newVaultDBConnector() = %#v, want nil", connector)
	}
}

func TestNewVaultDBConnectorFailsForDisallowedRole(t *testing.T) {
	t.Setenv("ASB_VAULT_ADDR", "https://vault.internal")
	t.Setenv("ASB_VAULT_DSN_TEMPLATE", "postgres://{{username}}:{{password}}@db.internal/app")
	t.Setenv("ASB_VAULT_ROLE", "analytics_readonly")
	t.Setenv("ASB_VAULT_ALLOWED_ROLE_SUFFIXES", "_ro")

	connector, err := newVaultDBConnector()
	if err == nil || !strings.Contains(err.Error(), "allowed suffixes") {
		t.Fatalf("newVaultDBConnector() error = %v, want allowed suffix validation error", err)
	}
	if connector != nil {
		t.Fatalf("newVaultDBConnector() = %#v, want nil", connector)
	}
}
