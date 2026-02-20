package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keksclan/goAuthly/authly"
)

type introResp struct {
	Active bool   `json:"active"`
	Scope  string `json:"scope"`
	Sub    string `json:"sub"`
	Exp    int64  `json:"exp"`
}

func TestEngineOpaque_IntrospectionAndCache(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(introResp{Active: true, Scope: "read write", Sub: "user42", Exp: time.Now().Add(1 * time.Minute).Unix()})
	}))
	defer server.Close()

	cfg := authly.Config{OAuth2: authly.OAuth2Config{
		Mode:                  authly.OAuth2OpaqueOnly,
		Introspection:         authly.IntrospectionConfig{Endpoint: server.URL, Timeout: 3 * time.Second},
		IntrospectionCacheTTL: 30 * time.Second,
	}}
	e, err := authly.New(cfg)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	res, err := e.Verify(context.Background(), "opaque-token-123")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Type != authly.TokenTypeOpaque {
		t.Fatalf("expected opaque token type")
	}
	if res.Subject != "user42" {
		t.Fatalf("subject mismatch: %s", res.Subject)
	}
	if len(res.Scopes) != 2 {
		t.Fatalf("expected 2 scopes")
	}

	// second call should hit cache
	_, _ = e.Verify(context.Background(), "opaque-token-123")
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 introspection request, got %d", hits)
	}
}
