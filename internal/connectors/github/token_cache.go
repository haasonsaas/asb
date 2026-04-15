package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const defaultRepoInstallationTTL = 24 * time.Hour

type AppTokenCache interface {
	GetRepoInstallation(ctx context.Context, repoKey string) (int64, bool, error)
	SetRepoInstallation(ctx context.Context, repoKey string, installationID int64) error
	GetInstallationToken(ctx context.Context, installationID int64) (cachedInstallationToken, bool, error)
	SetInstallationToken(ctx context.Context, installationID int64, token cachedInstallationToken) error
}

type RedisAppTokenCacheConfig struct {
	Client              goredis.UniversalClient
	KeyPrefix           string
	RepoInstallationTTL time.Duration
}

type redisAppTokenCache struct {
	client              goredis.UniversalClient
	keyPrefix           string
	repoInstallationTTL time.Duration
}

type redisCachedInstallationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewRedisAppTokenCache(cfg RedisAppTokenCacheConfig) AppTokenCache {
	if cfg.Client == nil {
		return nil
	}
	if cfg.RepoInstallationTTL <= 0 {
		cfg.RepoInstallationTTL = defaultRepoInstallationTTL
	}
	return &redisAppTokenCache{
		client:              cfg.Client,
		keyPrefix:           strings.TrimSpace(cfg.KeyPrefix),
		repoInstallationTTL: cfg.RepoInstallationTTL,
	}
}

func (c *redisAppTokenCache) GetRepoInstallation(ctx context.Context, repoKey string) (int64, bool, error) {
	value, err := c.client.Get(ctx, c.repoInstallationKey(repoKey)).Result()
	if err == goredis.Nil {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	installationID, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false, err
	}
	return installationID, true, nil
}

func (c *redisAppTokenCache) SetRepoInstallation(ctx context.Context, repoKey string, installationID int64) error {
	return c.client.Set(
		ctx,
		c.repoInstallationKey(repoKey),
		strconv.FormatInt(installationID, 10),
		c.repoInstallationTTL,
	).Err()
}

func (c *redisAppTokenCache) GetInstallationToken(ctx context.Context, installationID int64) (cachedInstallationToken, bool, error) {
	value, err := c.client.Get(ctx, c.installationTokenKey(installationID)).Bytes()
	if err == goredis.Nil {
		return cachedInstallationToken{}, false, nil
	}
	if err != nil {
		return cachedInstallationToken{}, false, err
	}
	var cached cachedInstallationToken
	var payload redisCachedInstallationToken
	if err := json.Unmarshal(value, &payload); err != nil {
		return cachedInstallationToken{}, false, err
	}
	cached.token = payload.Token
	cached.expiresAt = payload.ExpiresAt
	return cached, true, nil
}

func (c *redisAppTokenCache) SetInstallationToken(ctx context.Context, installationID int64, token cachedInstallationToken) error {
	ttl := time.Until(token.expiresAt)
	if ttl <= 0 {
		return nil
	}
	payload, err := json.Marshal(redisCachedInstallationToken{
		Token:     token.token,
		ExpiresAt: token.expiresAt,
	})
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.installationTokenKey(installationID), payload, ttl).Err()
}

func (c *redisAppTokenCache) repoInstallationKey(repoKey string) string {
	return fmt.Sprintf("%sgithub:repo-installation:%s", c.keyPrefix, repoKey)
}

func (c *redisAppTokenCache) installationTokenKey(installationID int64) string {
	return fmt.Sprintf("%sgithub:installation-token:%d", c.keyPrefix, installationID)
}
