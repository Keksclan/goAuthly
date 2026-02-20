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

	"github.com/keksclan/goAuthly/authly"
	jwxjwk "github.com/lestrrat-go/jwx/v2/jwk"
)

// assertNotPanics fails the test if f panics.
func assertNotPanics(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	f()
}

func startDemoServer(t *testing.T) *httptest.Server {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	pub := &priv.PublicKey

	// Build JWKS
	key, err := jwxjwk.FromRaw(pub)
	if err != nil {
		t.Fatalf("jwk: %v", err)
	}
	_ = key.Set(jwxjwk.KeyIDKey, "demo-kid")
	_ = key.Set(jwxjwk.AlgorithmKey, "RS256")
	set := jwxjwk.NewSet()
	set.AddKey(key)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tok := r.Form.Get("token")
		switch tok {
		case "opaque-json-bad":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("{bad json"))
			return
		case "opaque-500":
			w.WriteHeader(http.StatusInternalServerError)
			return
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
		}
	})
	return httptest.NewServer(mux)
}

func newEngineForNoPanic(t *testing.T, baseURL string) *authly.Engine {
	t.Helper()
	cfg := authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:                  authly.OAuth2JWTAndOpaque,
			Issuer:                "https://issuer.demo",
			Audience:              "demo-api",
			AllowedAlgs:           []string{"RS256"},
			JWKSURL:               baseURL + "/.well-known/jwks.json",
			JWKSCacheTTL:          time.Minute,
			AllowStaleJWKS:        true,
			Introspection:         authly.IntrospectionConfig{Endpoint: baseURL + "/introspect", Timeout: time.Second},
			IntrospectionCacheTTL: 10 * time.Second,
		},
	}
	eng, err := authly.New(cfg)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng
}

func TestVerify_NoPanics(t *testing.T) {
	ts := startDemoServer(t)
	defer ts.Close()
	eng := newEngineForNoPanic(t, ts.URL)
	ctx := context.Background()

	cases := []string{
		"",                      // empty
		"abc",                   // random string
		"a.b",                   // malformed jwt (2 parts)
		"a.b.c",                 // malformed jwt (3 parts but garbage)
		"opaque-json-bad",       // introspection returns bad JSON
		"opaque-500",            // introspection returns 500
		"opaque-something-else", // inactive token
	}

	for _, tok := range cases {
		assertNotPanics(t, func() {
			_, _ = eng.Verify(ctx, tok)
		})
	}
}
