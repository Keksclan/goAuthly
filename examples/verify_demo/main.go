package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/authly"
	jwxjwk "github.com/lestrrat-go/jwx/v2/jwk"
)

// demoJWKSHandler serves a JWKS containing the provided public key with kid "demo-kid".
func demoJWKSHandler(pub *rsa.PublicKey) http.HandlerFunc {
	// Build JWKS once for efficiency
	key, err := jwxjwk.FromRaw(pub)
	if err != nil {
		panic(err) // example panic is acceptable in example code to simplify
	}
	_ = key.Set(jwxjwk.KeyIDKey, "demo-kid")
	_ = key.Set(jwxjwk.AlgorithmKey, "RS256")
	set := jwxjwk.NewSet()
	set.AddKey(key)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		_ = enc.Encode(set) // encode never errors for jwk.Set
	}
}

// demoIntrospectHandler implements a tiny RFC7662-like endpoint.
func demoIntrospectHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok := r.Form.Get("token")
	w.Header().Set("Content-Type", "application/json")
	if tok == "opaque-good" {
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "user-456",
			"scope":  "read",
			"exp":    time.Now().Add(5 * time.Minute).Unix(),
			"act":    map[string]any{"sub": "service-a"},
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"active": false})
}

func mintDemoJWT(priv *rsa.PrivateKey) (string, error) {
	claims := jwt.MapClaims{
		"iss":   "https://issuer.demo",
		"aud":   "demo-api",
		"sub":   "user-123",
		"scope": "read write",
		"act":   map[string]any{"sub": "service-a"},
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "demo-kid"
	return tok.SignedString(priv)
}

func prettyPrintResult(prefix string, res *authly.Result) {
	actor := "<none>"
	if res.Actor != nil {
		actor = res.Actor.Subject
	}
	fmt.Printf("%s: type=%s subject=%s scopes=%s actor=%s expires=%s\n",
		prefix, res.Type, res.Subject, strings.Join(res.Scopes, ","), actor, res.ExpiresAt.Format(time.RFC3339))
}

func main() {
	// 1) Generate an RSA keypair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate RSA: %v", err)
	}
	pub := &priv.PublicKey

	// 2) Start local HTTP server exposing JWKS and Introspection
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", demoJWKSHandler(pub))
	mux.HandleFunc("/introspect", demoIntrospectHandler)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	jwksURL := ts.URL + "/.well-known/jwks.json"
	introURL := ts.URL + "/introspect"

	fmt.Println("Demo endpoints:")
	fmt.Println("  JWKS:", jwksURL)
	fmt.Println("  Introspection:", introURL)

	// 3) Mint a signed JWT and define an opaque token
	jwtToken, err := mintDemoJWT(priv)
	if err != nil {
		log.Fatalf("mint jwt: %v", err)
	}
	opaque := "opaque-good"

	// 4) Build goAuthly Engine in JWTAndOpaque mode with policies
	cfg := authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:           authly.OAuth2JWTAndOpaque,
			Issuer:         "https://issuer.demo",
			Audience:       "demo-api",
			AllowedAlgs:    []string{"RS256"},
			JWKSURL:        jwksURL,
			JWKSCacheTTL:   5 * time.Minute,
			AllowStaleJWKS: true,
			Introspection: authly.IntrospectionConfig{
				Endpoint: introURL,
				Timeout:  2 * time.Second,
			},
			IntrospectionCacheTTL: 30 * time.Second,
		},
		Policies: authly.Policies{
			TokenClaims: authly.ClaimPolicy{
				Required:  []string{"sub"},
				Allowlist: []string{"sub", "iss", "aud", "exp", "iat", "nbf", "scope", "act", "active"},
			},
			Actor: authly.ActorPolicy{
				Enabled:              true,
				ActorClaimKey:        "act",
				AllowedActorSubjects: []string{"service-a"},
			},
		},
	}

	eng, err := authly.New(cfg, authly.WithKeepRawToken())
	if err != nil {
		log.Fatalf("init engine: %v", err)
	}

	ctx := context.Background()

	// 5) Verify JWT token
	jwtRes, err := eng.Verify(ctx, jwtToken)
	if err != nil {
		log.Fatalf("verify jwt: %v", err)
	}
	prettyPrintResult("JWT", jwtRes)

	// 6) Verify opaque token
	opRes, err := eng.Verify(ctx, opaque)
	if err != nil {
		log.Fatalf("verify opaque: %v", err)
	}
	prettyPrintResult("Opaque", opRes)

	fmt.Println("Done.")
}
