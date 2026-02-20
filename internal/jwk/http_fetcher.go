package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type HTTPProvider struct {
	mu      sync.RWMutex
	httpc   *http.Client
	jwksSet jwk.Set
}

func NewHTTPProvider() *HTTPProvider {
	return &HTTPProvider{httpc: &http.Client{Timeout: 5 * time.Second}}
}

func (p *HTTPProvider) GetKey(ctx context.Context, kid string) (any, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.jwksSet == nil {
		return nil, ErrNoJWKSLoaded
	}

	key, ok := p.jwksSet.LookupKeyID(kid)
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

func (p *HTTPProvider) LoadFromURL(ctx context.Context, jwksURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status %d", resp.StatusCode)
	}

	set, err := jwk.ParseReader(io.LimitReader(resp.Body, maxJWKSResponseSize))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJWKS, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.jwksSet = set

	return nil
}
