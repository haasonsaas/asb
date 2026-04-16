package toolregistry

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/evalops/asb/internal/core"
)

func TestPutRejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()

	registry := New()

	for _, tc := range []struct {
		name string
		tool core.Tool
	}{
		{
			name: "missing tenant",
			tool: core.Tool{
				Tool: "github",
			},
		},
		{
			name: "missing tool",
			tool: core.Tool{
				TenantID: "tenant_123",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := registry.Put(context.Background(), tc.tool)
			if !errors.Is(err, core.ErrInvalidRequest) {
				t.Fatalf("Put() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestGetReturnsNotFoundForUnknownTool(t *testing.T) {
	t.Parallel()

	registry := New()

	_, err := registry.Get(context.Background(), "tenant_123", "github")
	if !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestPutAndGetRoundTrip(t *testing.T) {
	t.Parallel()

	registry := New()
	want := core.Tool{
		TenantID:             "tenant_123",
		Tool:                 "github",
		ManifestHash:         "sha256:abc123",
		RuntimeClass:         core.RuntimeClassHosted,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		AllowedCapabilities:  []string{"repo:read", "repo:write"},
		EgressAllowlist:      []string{"api.github.com"},
		LoggingMode:          "full",
		TrustTags:            []string{"gitops"},
	}

	if err := registry.Put(context.Background(), want); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := registry.Get(context.Background(), want.TenantID, want.Tool)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got == nil {
		t.Fatal("Get() returned nil tool")
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("Get() = %#v, want %#v", *got, want)
	}
}

func TestGetReturnsCopy(t *testing.T) {
	t.Parallel()

	registry := New()
	tool := core.Tool{
		TenantID:     "tenant_123",
		Tool:         "github",
		ManifestHash: "sha256:abc123",
	}

	if err := registry.Put(context.Background(), tool); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := registry.Get(context.Background(), tool.TenantID, tool.Tool)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	got.ManifestHash = "sha256:mutated"

	reloaded, err := registry.Get(context.Background(), tool.TenantID, tool.Tool)
	if err != nil {
		t.Fatalf("Get() reload error = %v", err)
	}
	if reloaded.ManifestHash != tool.ManifestHash {
		t.Fatalf("reloaded ManifestHash = %q, want %q", reloaded.ManifestHash, tool.ManifestHash)
	}
}

func TestPutOverwritesExistingEntry(t *testing.T) {
	t.Parallel()

	registry := New()
	original := core.Tool{
		TenantID:     "tenant_123",
		Tool:         "github",
		ManifestHash: "sha256:old",
	}
	updated := core.Tool{
		TenantID:     "tenant_123",
		Tool:         "github",
		ManifestHash: "sha256:new",
	}

	if err := registry.Put(context.Background(), original); err != nil {
		t.Fatalf("Put() original error = %v", err)
	}
	if err := registry.Put(context.Background(), updated); err != nil {
		t.Fatalf("Put() updated error = %v", err)
	}

	got, err := registry.Get(context.Background(), updated.TenantID, updated.Tool)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ManifestHash != updated.ManifestHash {
		t.Fatalf("ManifestHash = %q, want %q", got.ManifestHash, updated.ManifestHash)
	}
}
