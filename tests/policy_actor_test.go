package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/authly"
	jwxjwk "github.com/lestrrat-go/jwx/v2/jwk"
)

func makeJWKS2(pub *rsa.PublicKey, kid string) []byte {
	set := jwxjwk.NewSet()
	k, _ := jwxjwk.FromRaw(pub)
	_ = jwxjwk.AssignKeyID(k)
	_ = k.Set(jwxjwk.KeyIDKey, kid)
	set.AddKey(k)
	b, _ := json.Marshal(set)
	return b
}

func signJWT2(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestActorPolicy_ObjectAndString(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	kid := "kid-act"
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeJWKS2(pub, kid))
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
	}, Policies: authly.Policies{Actor: authly.ActorPolicy{Enabled: true, ActorClaimKey: "act", AllowedActorSubjects: []string{"service-a"}}}}

	e, _ := authly.New(cfg)
	exp := time.Now().Add(5 * time.Minute).Unix()

	// Object form
	t1 := signJWT2(t, priv, kid, jwt.MapClaims{"iss": "i", "aud": "a", "sub": "u", "exp": exp, "act": map[string]any{"sub": "service-a"}})
	res, err := e.Verify(context.Background(), t1)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Actor == nil || res.Actor.Subject != "service-a" {
		t.Fatalf("actor not extracted correctly")
	}

	// Missing actor -> error
	t2 := signJWT2(t, priv, kid, jwt.MapClaims{"iss": "i", "aud": "a", "sub": "u", "exp": exp})
	if _, err := e.Verify(context.Background(), t2); err == nil {
		t.Fatalf("expected error for missing actor")
	}

	// String form
	t3 := signJWT2(t, priv, kid, jwt.MapClaims{"iss": "i", "aud": "a", "sub": "u", "exp": exp, "act": "service-a"})
	res, err = e.Verify(context.Background(), t3)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Actor == nil || res.Actor.Subject != "service-a" {
		t.Fatalf("actor not extracted correctly (string)")
	}
}
