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
	t.Setenv("ASB_HTTP_READY_TIMEOUT", "")
	t.Setenv("ASB_HTTP_SHUTDOWN_TIMEOUT", "")
	t.Setenv("ASB_HTTP_DEFAULT_TIMEOUT", "")
	t.Setenv("ASB_HTTP_GRANT_TIMEOUT", "")
	t.Setenv("ASB_HTTP_PROXY_TIMEOUT", "")
	t.Setenv("ASB_HTTP_RATE_LIMIT_RPS", "")
	t.Setenv("ASB_HTTP_RATE_LIMIT_BURST", "")
	t.Setenv("ASB_HTTP_RATE_LIMIT_MAX_AGE", "")
	t.Setenv("ASB_HTTP_RATE_LIMIT_CLEANUP_INTERVAL", "")

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
	if cfg.readyTimeout != 2*time.Second || cfg.shutdownTimeout != 30*time.Second {
		t.Fatalf("unexpected health/shutdown timeouts: %#v", cfg)
	}
	if cfg.rateLimitRPS != 100 || cfg.rateLimitBurst != 200 {
		t.Fatalf("unexpected rate limit config: %#v", cfg)
	}
}

func TestLoadServerConfigParsesOverrides(t *testing.T) {
	t.Setenv("ASB_ADDR", ":9090")
	t.Setenv("ASB_HTTP_MAX_BODY_BYTES", "2048")
	t.Setenv("ASB_HTTP_READ_TIMEOUT", "11s")
	t.Setenv("ASB_HTTP_WRITE_TIMEOUT", "41s")
	t.Setenv("ASB_HTTP_IDLE_TIMEOUT", "2m")
	t.Setenv("ASB_HTTP_READY_TIMEOUT", "3s")
	t.Setenv("ASB_HTTP_SHUTDOWN_TIMEOUT", "35s")
	t.Setenv("ASB_HTTP_DEFAULT_TIMEOUT", "9s")
	t.Setenv("ASB_HTTP_GRANT_TIMEOUT", "29s")
	t.Setenv("ASB_HTTP_PROXY_TIMEOUT", "45s")
	t.Setenv("ASB_HTTP_RATE_LIMIT_RPS", "7.5")
	t.Setenv("ASB_HTTP_RATE_LIMIT_BURST", "22")
	t.Setenv("ASB_HTTP_RATE_LIMIT_MAX_AGE", "9m")
	t.Setenv("ASB_HTTP_RATE_LIMIT_CLEANUP_INTERVAL", "75s")

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
	if cfg.readyTimeout != 3*time.Second || cfg.shutdownTimeout != 35*time.Second {
		t.Fatalf("unexpected health/shutdown timeouts: %#v", cfg)
	}
	if cfg.defaultTimeout != 9*time.Second || cfg.grantTimeout != 29*time.Second || cfg.proxyTimeout != 45*time.Second {
		t.Fatalf("unexpected request timeouts: %#v", cfg)
	}
	if cfg.rateLimitRPS != 7.5 || cfg.rateLimitBurst != 22 {
		t.Fatalf("unexpected rate limit config: %#v", cfg)
	}
	if cfg.rateLimitMaxAge != 9*time.Minute || cfg.rateLimitCleanup != 75*time.Second {
		t.Fatalf("unexpected rate limit durations: %#v", cfg)
	}
}

func TestLoadServerConfigRejectsInvalidValues(t *testing.T) {
	t.Setenv("ASB_HTTP_MAX_BODY_BYTES", "0")

	if _, err := loadServerConfig(); err == nil {
		t.Fatal("loadServerConfig() error = nil, want non-nil")
	}
}
