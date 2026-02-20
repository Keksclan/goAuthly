package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keksclan/goAuthly/internal/jwk"
	lestrratjwk "github.com/lestrrat-go/jwx/v2/jwk"
)

func TestJWKProvider(t *testing.T) {
	// Generate a test key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubKey := &privKey.PublicKey
	kid := "test-key-1"

	// Create a valid JWKS
	key, _ := lestrratjwk.FromRaw(pubKey)
	_ = key.Set(lestrratjwk.KeyIDKey, kid)
	set := lestrratjwk.NewSet()
	_ = set.AddKey(key)
	jwksJSON, _ := json.Marshal(set)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/valid":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksJSON)
		case "/invalid":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys": "not-an-array"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("No JWKS loaded", func(t *testing.T) {
		p := jwk.NewHTTPProvider()
		_, err := p.GetKey(ctx, kid)
		if !errors.Is(err, jwk.ErrNoJWKSLoaded) {
			t.Errorf("expected ErrNoJWKSLoaded, got %v", err)
		}
	})

	t.Run("Successful JWKS load", func(t *testing.T) {
		p := jwk.NewHTTPProvider()
		err := p.LoadFromURL(ctx, server.URL+"/valid")
		if err != nil {
			t.Fatalf("LoadFromURL failed: %v", err)
		}
	})

	t.Run("GetKey success", func(t *testing.T) {
		p := jwk.NewHTTPProvider()
		_ = p.LoadFromURL(ctx, server.URL+"/valid")
		key, err := p.GetKey(ctx, kid)
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}
		if _, ok := key.(*rsa.PublicKey); !ok {
			t.Errorf("expected *rsa.PublicKey, got %T", key)
		}
	})

	t.Run("Key not found", func(t *testing.T) {
		p := jwk.NewHTTPProvider()
		_ = p.LoadFromURL(ctx, server.URL+"/valid")
		_, err := p.GetKey(ctx, "unknown-kid")
		if !errors.Is(err, jwk.ErrKeyNotFound) {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("Invalid JWKS JSON", func(t *testing.T) {
		p := jwk.NewHTTPProvider()
		err := p.LoadFromURL(ctx, server.URL+"/invalid")
		if !errors.Is(err, jwk.ErrInvalidJWKS) {
			t.Errorf("expected ErrInvalidJWKS, got %v", err)
		}
	})
}
