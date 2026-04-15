package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/evalops/asb/internal/core"
	proxybudget "github.com/evalops/asb/internal/delivery/proxy"
)

type RuntimeStore struct {
	mu               sync.RWMutex
	budgets          map[string]*proxybudget.BudgetTracker
	relays           map[string]*core.BrowserRelaySession
	expires          map[string]time.Time
	tokenRevocations map[string]time.Time
}

func NewRuntimeStore() *RuntimeStore {
	return &RuntimeStore{
		budgets:          make(map[string]*proxybudget.BudgetTracker),
		relays:           make(map[string]*core.BrowserRelaySession),
		expires:          make(map[string]time.Time),
		tokenRevocations: make(map[string]time.Time),
	}
}

func (s *RuntimeStore) RegisterProxyHandle(_ context.Context, handle string, budget core.ProxyBudget, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.budgets[handle] = proxybudget.NewBudgetTracker(budget)
	s.expires[handle] = expiresAt
	return nil
}

func (s *RuntimeStore) AcquireProxyRequest(_ context.Context, handle string) error {
	s.mu.RLock()
	tracker, ok := s.budgets[handle]
	expiresAt := s.expires[handle]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("%w: proxy handle %q", core.ErrNotFound, handle)
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		return fmt.Errorf("%w: proxy handle %q expired", core.ErrForbidden, handle)
	}
	return tracker.Acquire()
}

func (s *RuntimeStore) CompleteProxyRequest(_ context.Context, handle string, responseBytes int64) error {
	s.mu.RLock()
	tracker, ok := s.budgets[handle]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("%w: proxy handle %q", core.ErrNotFound, handle)
	}
	return tracker.Complete(responseBytes)
}

func (s *RuntimeStore) SaveRelaySession(_ context.Context, relay *core.BrowserRelaySession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *relay
	if len(relay.Selectors) > 0 {
		cp.Selectors = make(map[string]string, len(relay.Selectors))
		for key, value := range relay.Selectors {
			cp.Selectors[key] = value
		}
	}
	s.relays[relay.SessionID] = &cp
	return nil
}

func (s *RuntimeStore) GetRelaySession(_ context.Context, sessionID string) (*core.BrowserRelaySession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	relay, ok := s.relays[sessionID]
	if !ok {
		return nil, fmt.Errorf("%w: relay session %q", core.ErrNotFound, sessionID)
	}
	if !relay.ExpiresAt.IsZero() && time.Now().After(relay.ExpiresAt) {
		return nil, fmt.Errorf("%w: relay session %q expired", core.ErrForbidden, sessionID)
	}
	cp := *relay
	if len(relay.Selectors) > 0 {
		cp.Selectors = make(map[string]string, len(relay.Selectors))
		for key, value := range relay.Selectors {
			cp.Selectors[key] = value
		}
	}
	return &cp, nil
}

func (s *RuntimeStore) RevokeSessionToken(_ context.Context, tokenID string, expiresAt time.Time) error {
	if tokenID == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokenRevocations[tokenID] = expiresAt
	return nil
}

func (s *RuntimeStore) IsSessionTokenRevoked(_ context.Context, tokenID string) (bool, error) {
	if tokenID == "" {
		return false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	expiresAt, ok := s.tokenRevocations[tokenID]
	if !ok {
		return false, nil
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		delete(s.tokenRevocations, tokenID)
		return false, nil
	}
	return true, nil
}
