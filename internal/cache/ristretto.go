package cache

import (
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto"
)

type RistrettoCache struct {
	cache *ristretto.Cache
}

func NewRistrettoCache(numCounters, maxCost int64, bufferItems int64) (*RistrettoCache, error) {
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ristretto cache: %w", err)
	}

	return &RistrettoCache{cache: cache}, nil
}

func (r *RistrettoCache) Get(key string) (any, bool) {
	return r.cache.Get(key)
}

func (r *RistrettoCache) Set(key string, value any, cost int64, ttl time.Duration) bool {
	return r.cache.SetWithTTL(key, value, cost, ttl)
}

func (r *RistrettoCache) Del(key string) {
	r.cache.Del(key)
}

// Wait flushes pending sets (useful for tests determinism)
func (r *RistrettoCache) Wait() { r.cache.Wait() }
