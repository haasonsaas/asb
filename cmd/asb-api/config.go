package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type serverConfig struct {
	addr           string
	maxBodyBytes   int64
	readTimeout    time.Duration
	writeTimeout   time.Duration
	idleTimeout    time.Duration
	defaultTimeout time.Duration
	grantTimeout   time.Duration
	proxyTimeout   time.Duration
}

func loadServerConfig() (serverConfig, error) {
	cfg := serverConfig{
		addr:           getenv("ASB_ADDR", ":8080"),
		maxBodyBytes:   1 << 20,
		readTimeout:    10 * time.Second,
		writeTimeout:   30 * time.Second,
		idleTimeout:    120 * time.Second,
		defaultTimeout: 10 * time.Second,
		grantTimeout:   20 * time.Second,
		proxyTimeout:   30 * time.Second,
	}

	var err error
	if cfg.maxBodyBytes, err = parsePositiveInt64Env("ASB_HTTP_MAX_BODY_BYTES", cfg.maxBodyBytes); err != nil {
		return serverConfig{}, err
	}
	if cfg.readTimeout, err = parsePositiveDurationEnv("ASB_HTTP_READ_TIMEOUT", cfg.readTimeout); err != nil {
		return serverConfig{}, err
	}
	if cfg.writeTimeout, err = parsePositiveDurationEnv("ASB_HTTP_WRITE_TIMEOUT", cfg.writeTimeout); err != nil {
		return serverConfig{}, err
	}
	if cfg.idleTimeout, err = parsePositiveDurationEnv("ASB_HTTP_IDLE_TIMEOUT", cfg.idleTimeout); err != nil {
		return serverConfig{}, err
	}
	if cfg.defaultTimeout, err = parsePositiveDurationEnv("ASB_HTTP_DEFAULT_TIMEOUT", cfg.defaultTimeout); err != nil {
		return serverConfig{}, err
	}
	if cfg.grantTimeout, err = parsePositiveDurationEnv("ASB_HTTP_GRANT_TIMEOUT", cfg.grantTimeout); err != nil {
		return serverConfig{}, err
	}
	if cfg.proxyTimeout, err = parsePositiveDurationEnv("ASB_HTTP_PROXY_TIMEOUT", cfg.proxyTimeout); err != nil {
		return serverConfig{}, err
	}

	return cfg, nil
}

func parsePositiveDurationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return value, nil
}

func parsePositiveInt64Env(key string, fallback int64) (int64, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return value, nil
}
