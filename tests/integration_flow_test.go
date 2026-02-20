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

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/internal/jwk"
	oauthjwt "github.com/keksclan/goAuthly/internal/oauth/jwt"
	lestrratjwk "github.com/lestrrat-go/jwx/v2/jwk"
)

func TestIntegration_Flow(t *testing.T) {
	// Generate RSA keypair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	pub := &priv.PublicKey
	kid := "test-key"

	// Build JWKS JSON
	jwkKey, err := lestrratjwk.FromRaw(pub)
	if err != nil {
		t.Fatalf("jwk from raw: %v", err)
	}
	_ = jwkKey.Set(lestrratjwk.KeyIDKey, kid)
	_ = jwkKey.Set(lestrratjwk.AlgorithmKey, "RS256")
	set := lestrratjwk.NewSet()
	_ = set.AddKey(jwkKey)
	jwksJSON, _ := json.Marshal(set)

	// Start JWKS server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	defer ts.Close()

	// Create JWT
	issuer := "https://issuer.test"
	audience := "api-service"
	now := time.Now()
	claims := gojwt.MapClaims{
		"iss":   issuer,
		"aud":   audience,
		"sub":   "user-123",
		"exp":   now.Add(10 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"scope": "read write",
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tokenString, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Load JWKS and validate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prov := jwk.NewHTTPProvider()
	if err := prov.LoadFromURL(ctx, ts.URL+"/jwks"); err != nil {
		t.Fatalf("load jwks: %v", err)
	}

	validator, err := oauthjwt.New(oauthjwt.Config{Issuer: issuer, Audience: audience}, prov)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	c, err := validator.Validate(ctx, tokenString)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	if c.Subject != "user-123" {
		t.Fatalf("want subject user-123, got %s", c.Subject)
	}
	if len(c.Scopes) != 2 || c.Scopes[0] != "read" || c.Scopes[1] != "write" {
		t.Fatalf("unexpected scopes: %#v", c.Scopes)
	}
}
