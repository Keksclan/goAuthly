package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keksclan/goAuthly/internal/cache"
	"github.com/keksclan/goAuthly/internal/jwk"
)

func serveJWKS(t *testing.T, checkFn func(r *http.Request)) *httptest.Server {
	t.Helper()
	// Generate a test EC key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := privKey.PublicKey

	// Build a minimal JWKS response
	jwksResp := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "test-kid",
				"x":   base64urlEncodeBigInt(pub.X),
				"y":   base64urlEncodeBigInt(pub.Y),
				"use": "sig",
			},
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checkFn != nil {
			checkFn(r)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResp)
	}))
}

func base64urlEncodeBigInt(n *big.Int) string {
	b := n.Bytes()
	// Pad to 32 bytes for P-256
	for len(b) < 32 {
		b = append([]byte{0}, b...)
	}
	return base64urlEncode(b)
}

func base64urlEncode(data []byte) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(data)*8+5)/6)
	padding := 0
	val := 0
	bits := 0
	for _, b := range data {
		val = (val << 8) | int(b)
		bits += 8
		for bits >= 6 {
			bits -= 6
			result = append(result, table[(val>>bits)&0x3f])
		}
	}
	if bits > 0 {
		val <<= (6 - bits)
		result = append(result, table[val&0x3f])
		padding = (6 - bits) / 2
	}
	_ = padding // no padding in base64url
	return string(result)
}

func newTestCache(t *testing.T) cache.Cache {
	t.Helper()
	c, err := cache.NewRistrettoCache(1<<15, 1<<20, 64)
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	return c
}

func TestJWKSBasicAuth(t *testing.T) {
	var receivedUser, receivedPass string
	var receivedOK bool

	server := serveJWKS(t, func(r *http.Request) {
		receivedUser, receivedPass, receivedOK = r.BasicAuth()
	})
	defer server.Close()

	c := newTestCache(t)
	m := jwk.NewManager(c, 5*time.Minute, false)
	m.SetAuth(jwk.AuthConfig{
		Kind:     jwk.AuthKindBasic,
		Username: "jwks-user",
		Password: "jwks-pass",
	})

	_, err := m.GetKey(context.Background(), server.URL, "test-kid")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}

	if !receivedOK {
		t.Fatal("basic auth not received")
	}
	if receivedUser != "jwks-user" {
		t.Errorf("username: want jwks-user, got %s", receivedUser)
	}
	if receivedPass != "jwks-pass" {
		t.Errorf("password: want jwks-pass, got %s", receivedPass)
	}
}

func TestJWKSBearerAuth(t *testing.T) {
	var receivedAuth string

	server := serveJWKS(t, func(r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
	})
	defer server.Close()

	c := newTestCache(t)
	m := jwk.NewManager(c, 5*time.Minute, false)
	m.SetAuth(jwk.AuthConfig{
		Kind:        jwk.AuthKindBearer,
		BearerToken: "my-jwks-bearer",
	})

	_, err := m.GetKey(context.Background(), server.URL, "test-kid")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}

	if receivedAuth != "Bearer my-jwks-bearer" {
		t.Errorf("bearer auth: want 'Bearer my-jwks-bearer', got %q", receivedAuth)
	}
}

func TestJWKSCustomHeaderAuth(t *testing.T) {
	var receivedHeader string

	server := serveJWKS(t, func(r *http.Request) {
		receivedHeader = r.Header.Get("X-Jwks-Key")
	})
	defer server.Close()

	c := newTestCache(t)
	m := jwk.NewManager(c, 5*time.Minute, false)
	m.SetAuth(jwk.AuthConfig{
		Kind:        jwk.AuthKindHeader,
		HeaderName:  "X-Jwks-Key",
		HeaderValue: "secret123",
	})

	_, err := m.GetKey(context.Background(), server.URL, "test-kid")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}

	if receivedHeader != "secret123" {
		t.Errorf("custom header: want secret123, got %s", receivedHeader)
	}
}

func TestJWKSExtraHeaders(t *testing.T) {
	var receivedH1, receivedH2 string

	server := serveJWKS(t, func(r *http.Request) {
		receivedH1 = r.Header.Get("X-Custom-1")
		receivedH2 = r.Header.Get("X-Custom-2")
	})
	defer server.Close()

	c := newTestCache(t)
	m := jwk.NewManager(c, 5*time.Minute, false)
	m.SetExtraHeaders(map[string]string{
		"X-Custom-1": "val1",
		"X-Custom-2": "val2",
	})

	_, err := m.GetKey(context.Background(), server.URL, "test-kid")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}

	if receivedH1 != "val1" {
		t.Errorf("extra header 1: want val1, got %s", receivedH1)
	}
	if receivedH2 != "val2" {
		t.Errorf("extra header 2: want val2, got %s", receivedH2)
	}
}
