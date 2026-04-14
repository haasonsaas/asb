package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type serverConfig struct {
	addr             string
	maxBodyBytes     int64
	readTimeout      time.Duration
	writeTimeout     time.Duration
	idleTimeout      time.Duration
	readyTimeout     time.Duration
	shutdownTimeout  time.Duration
	defaultTimeout   time.Duration
	grantTimeout     time.Duration
	proxyTimeout     time.Duration
	rateLimitRPS     float64
	rateLimitBurst   int
	rateLimitMaxAge  time.Duration
	rateLimitCleanup time.Duration
}

func loadServerConfig() (serverConfig, error) {
	cfg := serverConfig{
		addr:             getenv("ASB_ADDR", ":8080"),
		maxBodyBytes:     1 << 20,
		readTimeout:      10 * time.Second,
		writeTimeout:     30 * time.Second,
		idleTimeout:      120 * time.Second,
		readyTimeout:     2 * time.Second,
		shutdownTimeout:  30 * time.Second,
		defaultTimeout:   10 * time.Second,
		grantTimeout:     20 * time.Second,
		proxyTimeout:     30 * time.Second,
		rateLimitRPS:     100,
		rateLimitBurst:   200,
		rateLimitMaxAge:  5 * time.Minute,
		rateLimitCleanup: time.Minute,
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
	if cfg.readyTimeout, err = parsePositiveDurationEnv("ASB_HTTP_READY_TIMEOUT", cfg.readyTimeout); err != nil {
		return serverConfig{}, err
	}
	if cfg.shutdownTimeout, err = parsePositiveDurationEnv("ASB_HTTP_SHUTDOWN_TIMEOUT", cfg.shutdownTimeout); err != nil {
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
	if cfg.rateLimitRPS, err = parsePositiveFloatEnv("ASB_HTTP_RATE_LIMIT_RPS", cfg.rateLimitRPS); err != nil {
		return serverConfig{}, err
	}
	if cfg.rateLimitBurst, err = parsePositiveIntEnv("ASB_HTTP_RATE_LIMIT_BURST", cfg.rateLimitBurst); err != nil {
		return serverConfig{}, err
	}
	if cfg.rateLimitMaxAge, err = parsePositiveDurationEnv("ASB_HTTP_RATE_LIMIT_MAX_AGE", cfg.rateLimitMaxAge); err != nil {
		return serverConfig{}, err
	}
	if cfg.rateLimitCleanup, err = parsePositiveDurationEnv("ASB_HTTP_RATE_LIMIT_CLEANUP_INTERVAL", cfg.rateLimitCleanup); err != nil {
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

func parsePositiveIntEnv(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return value, nil
}

func parsePositiveFloatEnv(key string, fallback float64) (float64, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return value, nil
}
