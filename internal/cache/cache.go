package cache

import (
	"time"
)

type Cache interface {
	Get(key string) (any, bool)
	Set(key string, value any, cost int64, ttl time.Duration) bool
	Del(key string)
}
