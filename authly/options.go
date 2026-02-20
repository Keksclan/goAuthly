package authly

import (
	"net/http"
	"time"
)

type Cache interface {
	Get(key string) (any, bool)
	Set(key string, value any, cost int64, ttl time.Duration) bool
	Del(key string)
}

type Option func(*Engine)

func WithHTTPClient(c *http.Client) Option {
	return func(e *Engine) {
		e.httpc = c
	}
}

func WithCache(c Cache) Option {
	return func(e *Engine) {
		e.cache = c
	}
}

func WithKeepRawToken() Option {
	return func(e *Engine) {
		e.keepRawToken = true
	}
}
