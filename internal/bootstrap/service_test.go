package bootstrap

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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

func TestNewVerifierReturnsOIDCVerifierWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	publicKeyPath := writeEd25519PublicKeyFile(t, dir, "oidc.pub.pem")

	t.Setenv("ASB_K8S_ISSUER", "")
	t.Setenv("ASB_K8S_PUBLIC_KEY_FILE", "")
	t.Setenv("ASB_OIDC_ISSUER", "https://token.actions.githubusercontent.com")
	t.Setenv("ASB_OIDC_PUBLIC_KEY_FILE", publicKeyPath)
	t.Setenv("ASB_OIDC_AUDIENCE", "asb-control-plane")
	t.Setenv("ASB_OIDC_ALLOWED_SUBJECT_PREFIXES", "repo:evalops/")

	verifier, err := newVerifier(true)
	if err != nil {
		t.Fatalf("newVerifier() error = %v", err)
	}
	if verifier == nil {
		t.Fatal("newVerifier() = nil, want configured verifier")
	}
}

func TestNewVerifierRequiresCompleteOIDCConfiguration(t *testing.T) {
	t.Setenv("ASB_K8S_ISSUER", "")
	t.Setenv("ASB_K8S_PUBLIC_KEY_FILE", "")
	t.Setenv("ASB_OIDC_ISSUER", "https://token.actions.githubusercontent.com")
	t.Setenv("ASB_OIDC_PUBLIC_KEY_FILE", "")

	verifier, err := newVerifier(true)
	if err == nil || !strings.Contains(err.Error(), "ASB_OIDC_ISSUER and ASB_OIDC_PUBLIC_KEY_FILE") {
		t.Fatalf("newVerifier() error = %v, want oidc config error", err)
	}
	if verifier != nil {
		t.Fatalf("newVerifier() = %#v, want nil", verifier)
	}
}

func TestNewBrowserConnectorDisabledByDefault(t *testing.T) {
	t.Setenv("ASB_BROWSER_ORIGIN", "")
	t.Setenv("ASB_BROWSER_USERNAME", "")
	t.Setenv("ASB_BROWSER_PASSWORD", "")
	t.Setenv("ASB_BROWSER_SELECTOR_USERNAME", "")
	t.Setenv("ASB_BROWSER_SELECTOR_PASSWORD", "")
	t.Setenv("ASB_BROWSER_ALLOW_INSECURE_LOCALHOST", "")

	connector, origin, err := newBrowserConnector()
	if err != nil {
		t.Fatalf("newBrowserConnector() error = %v", err)
	}
	if connector != nil || origin != "" {
		t.Fatalf("newBrowserConnector() = (%#v, %q), want disabled browser connector", connector, origin)
	}
}

func TestNewBrowserConnectorRequiresSelectors(t *testing.T) {
	t.Setenv("ASB_BROWSER_ORIGIN", "https://admin.vendor.example")
	t.Setenv("ASB_BROWSER_USERNAME", "admin")
	t.Setenv("ASB_BROWSER_PASSWORD", "secret")
	t.Setenv("ASB_BROWSER_SELECTOR_USERNAME", "")
	t.Setenv("ASB_BROWSER_SELECTOR_PASSWORD", "")

	connector, _, err := newBrowserConnector()
	if err == nil || !strings.Contains(err.Error(), "ASB_BROWSER_SELECTOR_USERNAME") {
		t.Fatalf("newBrowserConnector() error = %v, want selector requirement error", err)
	}
	if connector != nil {
		t.Fatalf("newBrowserConnector() = %#v, want nil", connector)
	}
}

func TestNewBrowserConnectorRejectsInsecureOriginByDefault(t *testing.T) {
	t.Setenv("ASB_BROWSER_ORIGIN", "http://localhost:3000")
	t.Setenv("ASB_BROWSER_USERNAME", "admin")
	t.Setenv("ASB_BROWSER_PASSWORD", "secret")
	t.Setenv("ASB_BROWSER_SELECTOR_USERNAME", "#username")
	t.Setenv("ASB_BROWSER_SELECTOR_PASSWORD", "#password")
	t.Setenv("ASB_BROWSER_ALLOW_INSECURE_LOCALHOST", "")

	connector, _, err := newBrowserConnector()
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("newBrowserConnector() error = %v, want https enforcement error", err)
	}
	if connector != nil {
		t.Fatalf("newBrowserConnector() = %#v, want nil", connector)
	}
}

func TestNewBrowserConnectorAllowsExplicitLocalhostOverride(t *testing.T) {
	t.Setenv("ASB_BROWSER_ORIGIN", "http://localhost:3000")
	t.Setenv("ASB_BROWSER_USERNAME", "admin")
	t.Setenv("ASB_BROWSER_PASSWORD", "secret")
	t.Setenv("ASB_BROWSER_SELECTOR_USERNAME", "#username")
	t.Setenv("ASB_BROWSER_SELECTOR_PASSWORD", "#password")
	t.Setenv("ASB_BROWSER_ALLOW_INSECURE_LOCALHOST", "true")

	connector, origin, err := newBrowserConnector()
	if err != nil {
		t.Fatalf("newBrowserConnector() error = %v", err)
	}
	if connector == nil || origin != "http://localhost:3000" {
		t.Fatalf("newBrowserConnector() = (%#v, %q), want configured localhost connector", connector, origin)
	}
}

func TestNewBrowserConnectorRejectsInvalidSelector(t *testing.T) {
	t.Setenv("ASB_BROWSER_ORIGIN", "https://admin.vendor.example")
	t.Setenv("ASB_BROWSER_USERNAME", "admin")
	t.Setenv("ASB_BROWSER_PASSWORD", "secret")
	t.Setenv("ASB_BROWSER_SELECTOR_USERNAME", "input[")
	t.Setenv("ASB_BROWSER_SELECTOR_PASSWORD", "#password")

	connector, _, err := newBrowserConnector()
	if err == nil || !strings.Contains(err.Error(), "invalid browser username selector") {
		t.Fatalf("newBrowserConnector() error = %v, want selector validation error", err)
	}
	if connector != nil {
		t.Fatalf("newBrowserConnector() = %#v, want nil", connector)
	}
}

func writeEd25519PublicKeyFile(t *testing.T, dir, name string) string {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: encoded}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
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
