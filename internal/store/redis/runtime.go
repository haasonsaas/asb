package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/evalops/asb/internal/core"
	goredis "github.com/redis/go-redis/v9"
)

type RuntimeStore struct {
	client goredis.UniversalClient
}

func NewRuntimeStore(client goredis.UniversalClient) *RuntimeStore {
	return &RuntimeStore{client: client}
}

func (s *RuntimeStore) RegisterProxyHandle(ctx context.Context, handle string, budget core.ProxyBudget, expiresAt time.Time) error {
	key := proxyKey(handle)
	fields := map[string]any{
		"max_concurrent": budget.MaxConcurrent,
		"max_requests":   budget.MaxRequests,
		"max_bytes":      budget.MaxBytes,
		"active":         0,
		"requests":       0,
		"bytes":          0,
	}
	if err := s.client.HSet(ctx, key, fields).Err(); err != nil {
		return err
	}
	if !expiresAt.IsZero() {
		if err := s.client.ExpireAt(ctx, key, expiresAt).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (s *RuntimeStore) AcquireProxyRequest(ctx context.Context, handle string) error {
	key := proxyKey(handle)
	for {
		err := s.client.Watch(ctx, func(tx *goredis.Tx) error {
			values, err := tx.HMGet(ctx, key, "max_concurrent", "max_requests", "active", "requests").Result()
			if err != nil {
				return err
			}
			if len(values) == 0 || values[0] == nil {
				return fmt.Errorf("%w: proxy handle %q", core.ErrNotFound, handle)
			}
			maxConcurrent := parseRedisInt(values[0])
			maxRequests := parseRedisInt(values[1])
			active := parseRedisInt(values[2])
			requests := parseRedisInt(values[3])
			if maxRequests > 0 && requests >= maxRequests {
				return core.ErrResourceBudgetExceeded
			}
			if maxConcurrent > 0 && active >= maxConcurrent {
				return core.ErrResourceBudgetExceeded
			}
			_, err = tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
				pipe.HIncrBy(ctx, key, "active", 1)
				pipe.HIncrBy(ctx, key, "requests", 1)
				return nil
			})
			return err
		}, key)
		if err == goredis.TxFailedErr {
			continue
		}
		return err
	}
}

func (s *RuntimeStore) CompleteProxyRequest(ctx context.Context, handle string, responseBytes int64) error {
	key := proxyKey(handle)
	for {
		var budgetExceeded bool
		err := s.client.Watch(ctx, func(tx *goredis.Tx) error {
			values, err := tx.HMGet(ctx, key, "max_bytes", "active", "bytes").Result()
			if err != nil {
				return err
			}
			if len(values) == 0 || values[0] == nil {
				return fmt.Errorf("%w: proxy handle %q", core.ErrNotFound, handle)
			}
			maxBytes := parseRedisInt64(values[0])
			active := parseRedisInt(values[1])
			bytesUsed := parseRedisInt64(values[2])
			nextActive := active - 1
			if nextActive < 0 {
				nextActive = 0
			}
			nextBytes := bytesUsed + responseBytes
			if maxBytes > 0 && nextBytes > maxBytes {
				budgetExceeded = true
			}
			_, err = tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
				pipe.HSet(ctx, key, "active", nextActive)
				pipe.HSet(ctx, key, "bytes", nextBytes)
				return nil
			})
			return err
		}, key)
		if err == goredis.TxFailedErr {
			continue
		}
		if err != nil {
			return err
		}
		if budgetExceeded {
			return core.ErrResourceBudgetExceeded
		}
		return nil
	}
}

func (s *RuntimeStore) SaveRelaySession(ctx context.Context, relay *core.BrowserRelaySession) error {
	selectorsJSON, err := json.Marshal(relay.Selectors)
	if err != nil {
		return err
	}
	key := relayKey(relay.SessionID)
	if err := s.client.HSet(ctx, key, map[string]any{
		"tenant_id":  relay.TenantID,
		"key_id":     relay.KeyID,
		"public_key": relay.PublicKey,
		"origin":     relay.Origin,
		"tab_id":     relay.TabID,
		"selectors":  selectorsJSON,
		"created_at": relay.CreatedAt.UTC().Format(time.RFC3339Nano),
		"expires_at": relay.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}).Err(); err != nil {
		return err
	}
	if !relay.ExpiresAt.IsZero() {
		if err := s.client.ExpireAt(ctx, key, relay.ExpiresAt).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (s *RuntimeStore) GetRelaySession(ctx context.Context, sessionID string) (*core.BrowserRelaySession, error) {
	values, err := s.client.HGetAll(ctx, relayKey(sessionID)).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: relay session %q", core.ErrNotFound, sessionID)
	}
	var selectors map[string]string
	if raw := values["selectors"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &selectors); err != nil {
			return nil, err
		}
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, values["created_at"])
	expiresAt, _ := time.Parse(time.RFC3339Nano, values["expires_at"])
	return &core.BrowserRelaySession{
		SessionID: sessionID,
		TenantID:  values["tenant_id"],
		KeyID:     values["key_id"],
		PublicKey: values["public_key"],
		Origin:    values["origin"],
		TabID:     values["tab_id"],
		Selectors: selectors,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *RuntimeStore) RevokeSessionToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	if tokenID == "" {
		return nil
	}

	key := revokedSessionTokenKey(tokenID)
	if err := s.client.Set(ctx, key, "1", 0).Err(); err != nil {
		return err
	}
	if !expiresAt.IsZero() {
		if err := s.client.ExpireAt(ctx, key, expiresAt).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (s *RuntimeStore) IsSessionTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	if tokenID == "" {
		return false, nil
	}

	exists, err := s.client.Exists(ctx, revokedSessionTokenKey(tokenID)).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func proxyKey(handle string) string {
	return "proxy:" + handle
}

func relayKey(sessionID string) string {
	return "relay:" + sessionID
}

func revokedSessionTokenKey(tokenID string) string {
	return "session_token_revoked:" + tokenID
}

func parseRedisInt(value any) int {
	switch v := value.(type) {
	case string:
		out, _ := strconv.Atoi(v)
		return out
	case int64:
		return int(v)
	default:
		return 0
	}
}

func parseRedisInt64(value any) int64 {
	switch v := value.(type) {
	case string:
		out, _ := strconv.ParseInt(v, 10, 64)
		return out
	case int64:
		return v
	default:
		return 0
	}
}
