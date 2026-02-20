package authly

import (
	"net/http"
	"time"
)

// Cache abstracts a tiny TTL cache used by Engine.
//
// Concurrency: Implementations must be safe for concurrent use.
type Cache interface {
	Get(key string) (any, bool)
	Set(key string, value any, cost int64, ttl time.Duration) bool
	Del(key string)
}

// Option configures Engine construction.
type Option func(*Engine)

// WithHTTPClient overrides the HTTP client used for JWKS and introspection.
func WithHTTPClient(c *http.Client) Option {
	return func(e *Engine) {
		e.httpc = c
	}
}

// WithCache overrides the cache used by the Engine.
func WithCache(c Cache) Option {
	return func(e *Engine) {
		e.cache = c
	}
}

// WithKeepRawToken instructs the Engine to include RawToken in Result.
func WithKeepRawToken() Option {
	return func(e *Engine) {
		e.keepRawToken = true
	}
}
