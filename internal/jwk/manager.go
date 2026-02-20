package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/keksclan/goAuthly/internal/cache"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/sync/singleflight"
)

// maxJWKSResponseSize limits the size of JWKS HTTP responses to prevent memory bombs.
const maxJWKSResponseSize = 1 << 20 // 1 MB

// AuthKind selects the authentication method for JWKS requests.
type AuthKind string

const (
	AuthKindNone   AuthKind = "none"
	AuthKindBasic  AuthKind = "basic"
	AuthKindBearer AuthKind = "bearer"
	AuthKindHeader AuthKind = "header"
)

// AuthConfig holds authentication settings for JWKS fetching.
type AuthConfig struct {
	Kind        AuthKind
	Username    string
	Password    string
	BearerToken string
	HeaderName  string
	HeaderValue string
}

type Manager struct {
	cache        cache.Cache
	httpc        *http.Client
	ttl          time.Duration
	allowStale   bool
	auth         AuthConfig
	extraHeaders map[string]string
	sfGroup      singleflight.Group

	// fetchOverride, when non-nil, replaces fetchSet inside the singleflight
	// closure. It exists solely as a testing seam so callers can inject a
	// result whose dynamic type is not jwk.Set.
	fetchOverride func(ctx context.Context, jwksURL string) (any, error)
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

// SetAuth configures authentication for JWKS requests.
func (m *Manager) SetAuth(auth AuthConfig) {
	m.auth = auth
}

// SetExtraHeaders configures additional headers for JWKS requests.
func (m *Manager) SetExtraHeaders(headers map[string]string) {
	m.extraHeaders = headers
}

func (m *Manager) GetKey(ctx context.Context, jwksURL, kid string) (any, error) {
	freshKey := "jwks:fresh:" + jwksURL
	staleKey := "jwks:stale:" + jwksURL

	if val, ok := m.cache.Get(freshKey); ok {
		if set, ok := val.(jwk.Set); ok && set != nil {
			return m.getKeyFromSet(set, kid)
		}
	}

	// Use singleflight to prevent stampede on concurrent cache misses.
	result, fetchErr, _ := m.sfGroup.Do(jwksURL, func() (any, error) {
		// Double-check cache inside singleflight (another goroutine may have populated it).
		if val, ok := m.cache.Get(freshKey); ok {
			if set, ok := val.(jwk.Set); ok && set != nil {
				return set, nil
			}
		}
		if m.fetchOverride != nil {
			return m.fetchOverride(ctx, jwksURL)
		}
		return m.fetchSet(ctx, jwksURL)
	})
	if fetchErr == nil {
		set, ok := result.(jwk.Set)
		if !ok {
			return nil, fmt.Errorf("unexpected singleflight result type %T for jwksURL=%s kid=%s", result, jwksURL, kid)
		}
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

	// Apply authentication
	m.applyAuth(req)

	// Apply extra headers
	for k, v := range m.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := m.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	set, err := jwk.ParseReader(io.LimitReader(resp.Body, maxJWKSResponseSize))
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	return set, nil
}

func (m *Manager) applyAuth(req *http.Request) {
	switch m.auth.Kind {
	case AuthKindBasic:
		req.SetBasicAuth(m.auth.Username, m.auth.Password)
	case AuthKindBearer:
		req.Header.Set("Authorization", "Bearer "+m.auth.BearerToken)
	case AuthKindHeader:
		if m.auth.HeaderName != "" {
			req.Header.Set(m.auth.HeaderName, m.auth.HeaderValue)
		}
	}
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
