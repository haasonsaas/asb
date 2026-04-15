package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/evalops/asb/internal/core"
	memstore "github.com/evalops/asb/internal/store/memory"
)

func TestRuntimeStore_ProxyBudgetsAndRelaySessions(t *testing.T) {
	t.Parallel()

	store := memstore.NewRuntimeStore()
	if err := store.RegisterProxyHandle(context.Background(), "ph_123", core.ProxyBudget{
		MaxConcurrent: 1,
		MaxRequests:   2,
		MaxBytes:      10,
	}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("RegisterProxyHandle() error = %v", err)
	}

	if err := store.AcquireProxyRequest(context.Background(), "ph_123"); err != nil {
		t.Fatalf("AcquireProxyRequest() error = %v", err)
	}
	if err := store.CompleteProxyRequest(context.Background(), "ph_123", 4); err != nil {
		t.Fatalf("CompleteProxyRequest() error = %v", err)
	}

	relay := &core.BrowserRelaySession{
		SessionID: "sess_abc",
		TenantID:  "t_acme",
		KeyID:     "key_1",
		PublicKey: "pub",
		Origin:    "https://admin.vendor.example",
		TabID:     "tab_42",
		Selectors: map[string]string{
			"username": "#username",
			"password": "#password",
		},
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
	}
	if err := store.SaveRelaySession(context.Background(), relay); err != nil {
		t.Fatalf("SaveRelaySession() error = %v", err)
	}
	got, err := store.GetRelaySession(context.Background(), "sess_abc")
	if err != nil {
		t.Fatalf("GetRelaySession() error = %v", err)
	}
	if got.KeyID != "key_1" || got.Selectors["username"] != "#username" {
		t.Fatalf("relay = %#v, want saved relay session", got)
	}

	if err := store.RevokeSessionToken(context.Background(), "tok_123", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("RevokeSessionToken() error = %v", err)
	}
	revoked, err := store.IsSessionTokenRevoked(context.Background(), "tok_123")
	if err != nil {
		t.Fatalf("IsSessionTokenRevoked() error = %v", err)
	}
	if !revoked {
		t.Fatal("IsSessionTokenRevoked() = false, want true")
	}
}
