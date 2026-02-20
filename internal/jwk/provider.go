package jwk

import (
	"context"
	"errors"
)

var (
	ErrKeyNotFound        = errors.New("key not found")
	ErrNoJWKSLoaded       = errors.New("no JWKS loaded")
	ErrInvalidJWKS        = errors.New("invalid JWKS")
	ErrUnsupportedKeyType = errors.New("unsupported key type")
)

type Provider interface {
	// GetKey returns a key usable for verifying JWT signatures.
	// It should locate the key by kid.
	GetKey(ctx context.Context, kid string) (any, error)

	// LoadFromURL loads/replaces the current key set from a JWKS URL.
	LoadFromURL(ctx context.Context, jwksURL string) error

	// Keys returns a snapshot (shallow copy) of all currently held kid->key pairs.
	Keys() map[string]any
}
