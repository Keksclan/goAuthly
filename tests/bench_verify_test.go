package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keksclan/goAuthly/authly"
	"github.com/keksclan/goAuthly/internal/luaengine"
)

// BenchmarkVerifyJWT measures the hot path for JWT verification with a cached JWKS.
func BenchmarkVerifyJWT(b *testing.B) {
	// Generate an ECDSA key pair for signing.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	// Serve JWKS endpoint.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x := privKey.PublicKey.X.Bytes()
		y := privKey.PublicKey.Y.Bytes()
		jwks := map[string]any{
			"keys": []map[string]any{{
				"kty": "EC",
				"crv": "P-256",
				"kid": "bench-key",
				"x":   base64.RawURLEncoding.EncodeToString(x),
				"y":   base64.RawURLEncoding.EncodeToString(y),
				"use": "sig",
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	eng, err := authly.New(authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:          authly.OAuth2JWTOnly,
			Issuer:        "https://bench.test",
			JWKSURL:       server.URL,
			Introspection: authly.IntrospectionConfig{Endpoint: "http://unused"},
			AllowedAlgs:   []string{"ES256"},
		},
	})
	if err != nil {
		b.Fatal(err)
	}

	// Sign a token.
	claims := jwt.MapClaims{
		"iss": "https://bench.test",
		"sub": "bench-user",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = "bench-key"
	signed, err := tok.SignedString(privKey)
	if err != nil {
		b.Fatal(err)
	}

	ctx := b.Context()
	// Warm up the JWKS cache.
	if _, err := eng.Verify(ctx, signed); err != nil {
		b.Fatalf("warmup verify failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := eng.Verify(ctx, signed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLuaPolicyEvaluate measures Lua policy evaluation overhead.
func BenchmarkLuaPolicyEvaluate(b *testing.B) {
	script := `
		require_claim("sub")
		require_claim("iss")
		if get("role") ~= "admin" then
			reject("not admin")
		end
	`
	cp, err := luaengine.Compile(script)
	if err != nil {
		b.Fatal(err)
	}
	claims := map[string]any{
		"sub":  "user-1",
		"iss":  "https://issuer.test",
		"role": "admin",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if err := cp.Evaluate(claims, "jwt"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAudienceValidate measures audience rule validation.
func BenchmarkAudienceValidate(b *testing.B) {
	rule := authly.AudienceRule{
		AllOf:     []string{"aud-1", "aud-2"},
		AnyOf:     []string{"aud-3", "aud-4"},
		Blocklist: []string{"blocked-1"},
	}
	tokenAud := []string{"aud-1", "aud-2", "aud-3", "aud-5"}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if err := rule.Validate(tokenAud); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIntrospectionCacheKey measures the cost of SHA-256 hashing for cache keys.
func BenchmarkIntrospectionCacheKey(b *testing.B) {
	eng, err := authly.New(authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:          authly.OAuth2OpaqueOnly,
			Issuer:        "https://bench.test",
			JWKSURL:       "http://unused",
			Introspection: authly.IntrospectionConfig{Endpoint: "http://unused"},
		},
	})
	if err != nil {
		b.Fatal(err)
	}

	// We can't directly benchmark the private method, but Verify with opaque
	// will exercise the cache key path before hitting the network.
	// Instead, benchmark the full verify path which will fail at introspection
	// but still exercise token hashing.
	ctx := b.Context()
	token := fmt.Sprintf("opaque-token-%d", time.Now().UnixNano())

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = eng.Verify(ctx, token)
	}
}
