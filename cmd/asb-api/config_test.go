package main

import (
	"testing"
	"time"
)

func TestLoadServerConfigDefaults(t *testing.T) {
	t.Setenv("ASB_ADDR", "")
	t.Setenv("ASB_HTTP_MAX_BODY_BYTES", "")
	t.Setenv("ASB_HTTP_READ_TIMEOUT", "")
	t.Setenv("ASB_HTTP_WRITE_TIMEOUT", "")
	t.Setenv("ASB_HTTP_IDLE_TIMEOUT", "")
	t.Setenv("ASB_HTTP_DEFAULT_TIMEOUT", "")
	t.Setenv("ASB_HTTP_GRANT_TIMEOUT", "")
	t.Setenv("ASB_HTTP_PROXY_TIMEOUT", "")

	cfg, err := loadServerConfig()
	if err != nil {
		t.Fatalf("loadServerConfig() error = %v", err)
	}
	if cfg.addr != ":8080" {
		t.Fatalf("addr = %q, want %q", cfg.addr, ":8080")
	}
	if cfg.maxBodyBytes != 1<<20 {
		t.Fatalf("maxBodyBytes = %d, want %d", cfg.maxBodyBytes, 1<<20)
	}
	if cfg.readTimeout != 10*time.Second || cfg.writeTimeout != 30*time.Second || cfg.idleTimeout != 120*time.Second {
		t.Fatalf("unexpected server timeouts: %#v", cfg)
	}
}

func TestLoadServerConfigParsesOverrides(t *testing.T) {
	t.Setenv("ASB_ADDR", ":9090")
	t.Setenv("ASB_HTTP_MAX_BODY_BYTES", "2048")
	t.Setenv("ASB_HTTP_READ_TIMEOUT", "11s")
	t.Setenv("ASB_HTTP_WRITE_TIMEOUT", "41s")
	t.Setenv("ASB_HTTP_IDLE_TIMEOUT", "2m")
	t.Setenv("ASB_HTTP_DEFAULT_TIMEOUT", "9s")
	t.Setenv("ASB_HTTP_GRANT_TIMEOUT", "29s")
	t.Setenv("ASB_HTTP_PROXY_TIMEOUT", "45s")

	cfg, err := loadServerConfig()
	if err != nil {
		t.Fatalf("loadServerConfig() error = %v", err)
	}
	if cfg.addr != ":9090" || cfg.maxBodyBytes != 2048 {
		t.Fatalf("unexpected basic config: %#v", cfg)
	}
	if cfg.readTimeout != 11*time.Second || cfg.writeTimeout != 41*time.Second || cfg.idleTimeout != 2*time.Minute {
		t.Fatalf("unexpected server timeouts: %#v", cfg)
	}
	if cfg.defaultTimeout != 9*time.Second || cfg.grantTimeout != 29*time.Second || cfg.proxyTimeout != 45*time.Second {
		t.Fatalf("unexpected request timeouts: %#v", cfg)
	}
}

func TestLoadServerConfigRejectsInvalidValues(t *testing.T) {
	t.Setenv("ASB_HTTP_MAX_BODY_BYTES", "0")

	if _, err := loadServerConfig(); err == nil {
		t.Fatal("loadServerConfig() error = nil, want non-nil")
	}
}
