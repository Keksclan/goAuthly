package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/authly"
	jwxjwk "github.com/lestrrat-go/jwx/v2/jwk"
)

func makeJWKS(pub *rsa.PublicKey, kid string) []byte {
	set := jwxjwk.NewSet()
	k, _ := jwxjwk.FromRaw(pub)
	_ = jwxjwk.AssignKeyID(k)
	_ = k.Set(jwxjwk.KeyIDKey, kid)
	set.AddKey(k)
	b, _ := json.Marshal(set)
	return b
}

func signJWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestEngineJWT_SuccessAndPolicies(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	kid := "kid1"
	jwksHits := 0
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksHits++
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeJWKS(pub, kid))
	}))
	defer jwksSrv.Close()

	issuer := "https://issuer.test"
	aud := "api"
	cfg := authly.Config{OAuth2: authly.OAuth2Config{
		Mode:                  authly.OAuth2JWTOnly,
		Issuer:                issuer,
		Audience:              aud,
		JWKSURL:               jwksSrv.URL,
		JWKSCacheTTL:          time.Minute,
		AllowStaleJWKS:        false,
		Introspection:         authly.IntrospectionConfig{Endpoint: "http://unused"},
		IntrospectionCacheTTL: 30 * time.Second,
	}, Policies: authly.Policies{TokenClaims: authly.ClaimPolicy{}}}

	e, err := authly.New(cfg)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	now := time.Now().Add(5 * time.Minute).Unix()
	token := signJWT(t, priv, kid, jwt.MapClaims{
		"iss": issuer,
		"aud": aud,
		"sub": "user1",
		"exp": now,
	})

	res, err := e.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Type != authly.TokenTypeJWT {
		t.Fatalf("expected jwt type")
	}
	if res.Subject != "user1" {
		t.Fatalf("subject mismatch")
	}
	if jwksHits != 1 {
		t.Fatalf("expected 1 jwks hit, got %d", jwksHits)
	}

	// Allowlist policy should reject unknown claims
	cfg.Policies.TokenClaims = authly.ClaimPolicy{Allowlist: []string{"iss", "aud", "sub", "exp"}}
	e, _ = authly.New(cfg)
	token2 := signJWT(t, priv, kid, jwt.MapClaims{
		"iss":  issuer,
		"aud":  aud,
		"sub":  "user1",
		"exp":  now,
		"role": "admin",
	})
	_, err = e.Verify(context.Background(), token2)
	if err == nil || !strings.Contains(err.Error(), authly.ErrUnknownClaimNotAllowed.Error()) {
		t.Fatalf("expected unknown claim error, got %v", err)
	}

	// Enforced values for a custom claim
	cfg.Policies.TokenClaims = authly.ClaimPolicy{EnforcedValues: map[string][]any{"tenant": {"t1"}}}
	e, _ = authly.New(cfg)
	token3 := signJWT(t, priv, kid, jwt.MapClaims{
		"iss":    issuer,
		"aud":    aud,
		"sub":    "user1",
		"exp":    now,
		"tenant": "t2",
	})
	_, err = e.Verify(context.Background(), token3)
	if err == nil || !strings.Contains(err.Error(), authly.ErrClaimValueNotAllowed.Error()) {
		t.Fatalf("expected enforced value error, got %v", err)
	}
}

func TestEngineJWKSCache(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	kid := "kid1"
	jwksHits := 0
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksHits++
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeJWKS(pub, kid))
	}))
	defer jwksSrv.Close()

	cfg := authly.Config{OAuth2: authly.OAuth2Config{
		Mode:                  authly.OAuth2JWTOnly,
		Issuer:                "i",
		Audience:              "a",
		JWKSURL:               jwksSrv.URL,
		JWKSCacheTTL:          time.Minute,
		Introspection:         authly.IntrospectionConfig{Endpoint: "http://unused"},
		IntrospectionCacheTTL: 30 * time.Second,
	}}
	e, _ := authly.New(cfg)

	now := time.Now().Add(5 * time.Minute).Unix()
	tok := signJWT(t, priv, kid, jwt.MapClaims{"iss": "i", "aud": "a", "sub": "u", "exp": now})
	_, _ = e.Verify(context.Background(), tok)
	_, _ = e.Verify(context.Background(), tok)
	if jwksHits != 1 {
		t.Fatalf("expected 1 jwks hit, got %d", jwksHits)
	}
}
