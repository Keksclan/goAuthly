package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/keksclan/goAuthly/internal/cache"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Manager struct {
	cache      cache.Cache
	httpc      *http.Client
	ttl        time.Duration
	allowStale bool
}

func (m *Manager) SetHTTPClient(c *http.Client) {
	if c != nil {
		m.httpc = c
	}
}

func NewManager(c cache.Cache, ttl time.Duration, allowStale bool) *Manager {
	return &Manager{
		cache:      c,
		httpc:      &http.Client{Timeout: 5 * time.Second},
		ttl:        ttl,
		allowStale: allowStale,
	}
}

func (m *Manager) GetKey(ctx context.Context, jwksURL, kid string) (any, error) {
	freshKey := "jwks:fresh:" + jwksURL
	staleKey := "jwks:stale:" + jwksURL

	if val, ok := m.cache.Get(freshKey); ok {
		if set, ok := val.(jwk.Set); ok && set != nil {
			return m.getKeyFromSet(set, kid)
		}
	}

	set, fetchErr := m.fetchSet(ctx, jwksURL)
	if fetchErr == nil {
		// store fresh and stale
		m.cache.Set(freshKey, set, 1, m.ttl)
		// keep stale longer (4x TTL, minimum 1h)
		staleTTL := max(m.ttl*4, time.Hour)
		m.cache.Set(staleKey, set, 1, staleTTL)
		// ensure visibility for immediate subsequent reads (ristretto is async)
		if w, ok := any(m.cache).(interface{ Wait() }); ok {
			w.Wait()
		}
		return m.getKeyFromSet(set, kid)
	}

	if m.allowStale {
		if val, ok := m.cache.Get(staleKey); ok {
			if set, ok := val.(jwk.Set); ok && set != nil {
				return m.getKeyFromSet(set, kid)
			}
		}
	}

	return nil, fmt.Errorf("failed to fetch JWKS: %w", fetchErr)
}

func (m *Manager) fetchSet(ctx context.Context, jwksURL string) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := m.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	set, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	return set, nil
}

func (m *Manager) getKeyFromSet(set jwk.Set, kid string) (any, error) {
	key, ok := set.LookupKeyID(kid)
	if !ok {
		return nil, ErrKeyNotFound
	}
	var rawKey any
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}
	switch rawKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return rawKey, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}
