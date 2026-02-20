// Package main demonstrates goAuthly with a fasthttp server.
//
// It starts a local JWKS + introspection mock, mints a demo JWT,
// and exposes three routes:
//
//	/public      — no authentication required
//	/protected   — requires Bearer token (JWT or opaque) + X-User-Sub header
//	/basic       — requires Basic auth credentials
//
// This is demo-only code. Do not use the generated keys or credentials in production.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jwxjwk "github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"

	authlyfasthttp "github.com/keksclan/goAuthly/adapters/fasthttp"
	"github.com/keksclan/goAuthly/authly"
)

// ---------------------------------------------------------------------------
// Mock JWKS + introspection handlers
// ---------------------------------------------------------------------------

// jwksHandler serves a JWKS containing the provided RSA public key.
func jwksHandler(pub *rsa.PublicKey) http.HandlerFunc {
	key, err := jwxjwk.FromRaw(pub)
	if err != nil {
		log.Fatalf("build JWK: %v", err)
	}
	if err := key.Set(jwxjwk.KeyIDKey, "demo-kid"); err != nil {
		log.Fatalf("set kid: %v", err)
	}
	if err := key.Set(jwxjwk.AlgorithmKey, "RS256"); err != nil {
		log.Fatalf("set alg: %v", err)
	}
	set := jwxjwk.NewSet()
	if err := set.AddKey(key); err != nil {
		log.Fatalf("add key: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}
}

// introspectHandler implements a tiny RFC 7662-like endpoint.
// Token "opaque-good" is active; everything else is inactive.
func introspectHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Form.Get("token") == "opaque-good" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "demo-user",
			"scope":  "read write",
			"exp":    time.Now().Add(5 * time.Minute).Unix(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
}

// ---------------------------------------------------------------------------
// JWT minting helper
// ---------------------------------------------------------------------------

func mintDemoJWT(priv *rsa.PrivateKey) (string, error) {
	claims := jwt.MapClaims{
		"iss":   "https://issuer.demo",
		"aud":   "demo-api",
		"sub":   "demo-user",
		"scope": "read write",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "demo-kid"
	return tok.SignedString(priv)
}

// ---------------------------------------------------------------------------
// fasthttp helpers
// ---------------------------------------------------------------------------

func writeJSON(ctx *fasthttp.RequestCtx, status int, v any) {
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json")
	body, err := json.Marshal(v)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString(`{"error":"internal error"}`)
		return
	}
	ctx.SetBody(body)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	// 1. Generate RSA key pair (demo only — never reuse in production).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	// 2. Start mock JWKS + introspection server.
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler(&priv.PublicKey))
	mux.HandleFunc("/introspect", introspectHandler)

	mockServer := &http.Server{
		Addr:              "127.0.0.1:9091",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := mockServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("mock server: %v", err)
		}
	}()
	// Give the mock server a moment to start.
	time.Sleep(100 * time.Millisecond)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = mockServer.Shutdown(ctx)
	}()

	jwksURL := "http://127.0.0.1:9091/.well-known/jwks.json"
	introURL := "http://127.0.0.1:9091/introspect"

	// 3. Mint a demo JWT and print example tokens.
	jwtToken, err := mintDemoJWT(priv)
	if err != nil {
		log.Fatalf("mint JWT: %v", err)
	}

	fmt.Println("=== Example Tokens ===")
	fmt.Println("JWT:", jwtToken)
	fmt.Println("Opaque: opaque-good")
	fmt.Println()

	// 4. Build goAuthly engines.

	// OAuth2 engine (JWT + opaque).
	oauthCfg := authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:        authly.OAuth2JWTAndOpaque,
			Issuer:      "https://issuer.demo",
			Audience:    "demo-api",
			AllowedAlgs: []string{"RS256"},
			JWKSURL:     jwksURL,
			Introspection: authly.IntrospectionConfig{
				Endpoint: introURL,
				Timeout:  2 * time.Second,
			},
		},
	}
	oauthEngine, err := authly.New(oauthCfg)
	if err != nil {
		log.Fatalf("init oauth engine: %v", err)
	}

	// Basic auth engine.
	// Demo credentials: user "demo" / password "password" (bcrypt hash).
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("bcrypt hash: %v", err)
	}

	basicCfg := authly.Config{
		Mode: authly.AuthModeBasic,
		BasicAuth: authly.BasicAuthConfig{
			Enabled: true,
			Users:   map[string]string{"demo": string(hash)},
			Realm:   "Demo",
		},
	}
	basicEngine, err := authly.New(basicCfg)
	if err != nil {
		log.Fatalf("init basic engine: %v", err)
	}

	// 5. Build fasthttp request handlers.

	publicHandler := func(ctx *fasthttp.RequestCtx) {
		writeJSON(ctx, fasthttp.StatusOK, map[string]string{
			"message": "public endpoint — no auth required",
		})
	}

	protectedNext := func(ctx *fasthttp.RequestCtx) {
		result := authlyfasthttp.ResultFromCtx(ctx)
		if result == nil {
			writeJSON(ctx, fasthttp.StatusUnauthorized, map[string]string{"error": "no auth result"})
			return
		}
		writeJSON(ctx, fasthttp.StatusOK, map[string]any{
			"subject":    result.Subject,
			"token_type": string(result.Type),
			"claims":     result.Claims,
		})
	}

	basicNext := func(ctx *fasthttp.RequestCtx) {
		result := authlyfasthttp.ResultFromCtx(ctx)
		if result == nil {
			writeJSON(ctx, fasthttp.StatusUnauthorized, map[string]string{"error": "no auth result"})
			return
		}
		writeJSON(ctx, fasthttp.StatusOK, map[string]any{
			"subject":    result.Subject,
			"token_type": string(result.Type),
			"claims":     result.Claims,
		})
	}

	protectedHandler := authlyfasthttp.Middleware(oauthEngine, protectedNext,
		authlyfasthttp.WithRequiredMetadata("X-User-Sub"),
	)
	basicHandler := authlyfasthttp.Middleware(basicEngine, basicNext)

	// 6. Simple path-based router.
	handler := func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/public":
			publicHandler(ctx)
		case "/protected":
			protectedHandler(ctx)
		case "/basic":
			basicHandler(ctx)
		default:
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("not found")
		}
	}

	// 7. Start fasthttp server.
	fmt.Println("fasthttp server listening on :8082")
	fmt.Println("Routes: /public, /protected, /basic")

	server := &fasthttp.Server{
		Handler:          handler,
		ReadTimeout:      5 * time.Second,
		WriteTimeout:     5 * time.Second,
		DisableKeepalive: false,
	}
	if err := server.ListenAndServe(":8082"); err != nil {
		log.Fatalf("fasthttp listen: %v", err)
	}
}
