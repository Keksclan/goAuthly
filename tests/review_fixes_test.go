package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keksclan/goAuthly/authly"
	"github.com/keksclan/goAuthly/internal/luaengine"
	"github.com/keksclan/goAuthly/internal/oauth/introspect"
)

// --- 1. Oversized introspection response is rejected ---

func TestIntrospection_OversizedResponse(t *testing.T) {
	// Server returns a response body larger than 1 MB.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a valid JSON start, then pad to exceed 1 MB.
		w.Write([]byte(`{"active":true,"padding":"`))
		buf := make([]byte, 1<<20) // 1 MB of padding
		for i := range buf {
			buf[i] = 'x'
		}
		w.Write(buf)
		w.Write([]byte(`"}`))
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(t.Context(), "some-token")
	if err == nil {
		t.Fatal("expected error for oversized response, got nil")
	}
	// The LimitReader truncates, so JSON parsing should fail.
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Fatalf("expected parse error from truncated body, got: %v", err)
	}
}

// --- 2. JWKS oversized response is rejected ---

func TestJWKS_OversizedResponse(t *testing.T) {
	// Server returns a JWKS response larger than 1 MB.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[`))
		buf := make([]byte, 1<<20)
		for i := range buf {
			buf[i] = 'x'
		}
		w.Write(buf)
		w.Write([]byte(`]}`))
	}))
	defer server.Close()

	eng, err := authly.New(authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:          authly.OAuth2JWTOnly,
			Issuer:        "https://issuer.test",
			JWKSURL:       server.URL,
			Introspection: authly.IntrospectionConfig{Endpoint: "http://unused"},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	// A JWT-looking token that will trigger JWKS fetch.
	fakeJWT := "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJpc3MiOiJ0ZXN0In0.sig"
	_, err = eng.Verify(t.Context(), fakeJWT)
	if err == nil {
		t.Fatal("expected error for oversized JWKS, got nil")
	}
}

// --- 3. Singleflight deduplicates concurrent JWKS fetches ---

func TestJWKS_SingleflightDedup(t *testing.T) {
	var fetchCount atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		// Small delay to allow concurrent requests to coalesce.
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		// Valid JWKS with an RSA key (minimal).
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{},
		})
	}))
	defer server.Close()

	eng, err := authly.New(authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:          authly.OAuth2JWTOnly,
			Issuer:        "https://issuer.test",
			JWKSURL:       server.URL,
			Introspection: authly.IntrospectionConfig{Endpoint: "http://unused"},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	fakeJWT := "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJpc3MiOiJ0ZXN0In0.sig"

	// Fire 10 concurrent requests.
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = eng.Verify(t.Context(), fakeJWT)
		}()
	}
	wg.Wait()

	// With singleflight, the server should have been hit far fewer than 10 times.
	count := fetchCount.Load()
	if count >= 5 {
		t.Fatalf("singleflight did not coalesce requests: %d fetches for 10 concurrent calls", count)
	}
}

// --- 4. Lua sandbox: loadstring is blocked ---

func TestLuaSandbox_LoadstringBlocked(t *testing.T) {
	script := `
		local fn = loadstring("return 1")
		if fn then
			reject("loadstring should not be available")
		end
	`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	claims := map[string]any{"sub": "test"}
	err = cp.Evaluate(claims, "jwt")
	// loadstring is nil, so calling it should produce a runtime error.
	if err == nil {
		t.Fatal("expected error when calling loadstring in sandbox")
	}
}

// --- 5. Lua sandbox: infinite loop times out ---

func TestLuaSandbox_InfiniteLoopTimeout(t *testing.T) {
	script := `while true do end`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	claims := map[string]any{"sub": "test"}
	err = cp.EvaluateWithTimeout(claims, "jwt", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error for infinite loop")
	}
	// EvaluateWithTimeout now applies both a timeout and a default instruction limit.
	// The infinite loop may be caught by either mechanism depending on timing.
	if !errors.Is(err, luaengine.ErrLuaTimeout) && !errors.Is(err, luaengine.ErrLuaInstructionLimit) {
		t.Fatalf("expected ErrLuaTimeout or ErrLuaInstructionLimit, got: %v", err)
	}
}

// --- 6. Lua sandbox: os/io/debug libraries not available ---

func TestLuaSandbox_DangerousLibsBlocked(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{"os", `if os then reject("os lib available") end`},
		{"io", `if io then reject("io lib available") end`},
		{"debug", `if debug then reject("debug lib available") end`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp, err := luaengine.Compile(tc.script)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			err = cp.Evaluate(map[string]any{"sub": "test"}, "jwt")
			if err != nil {
				t.Fatalf("unexpected error (lib %s should be nil, not error): %v", tc.name, err)
			}
		})
	}
}

// --- 7. Empty bearer token is rejected by Engine.Verify ---

func TestVerify_EmptyToken(t *testing.T) {
	eng, err := authly.New(authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:          authly.OAuth2JWTOnly,
			Issuer:        "https://issuer.test",
			JWKSURL:       "https://issuer.test/.well-known/jwks.json",
			Introspection: authly.IntrospectionConfig{Endpoint: "http://unused"},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	_, err = eng.Verify(context.Background(), "")
	if !errors.Is(err, authly.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty token, got: %v", err)
	}
}

// --- 8. Empty bearer token (whitespace only) after "Bearer " prefix ---

func TestVerify_WhitespaceToken(t *testing.T) {
	eng, err := authly.New(authly.Config{
		Mode: authly.AuthModeOAuth2,
		OAuth2: authly.OAuth2Config{
			Mode:          authly.OAuth2JWTOnly,
			Issuer:        "https://issuer.test",
			JWKSURL:       "https://issuer.test/.well-known/jwks.json",
			Introspection: authly.IntrospectionConfig{Endpoint: "http://unused"},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	_, err = eng.Verify(context.Background(), "   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only token")
	}
}
