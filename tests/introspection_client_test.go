package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keksclan/goAuthly/internal/oauth/introspect"
)

func TestIntrospectionClient(t *testing.T) {
	const (
		clientID     = "test-client"
		clientSecret = "test-secret"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != clientID || password != clientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		_ = r.ParseForm()
		token := r.FormValue("token")
		w.Header().Set("Content-Type", "application/json")

		switch token {
		case "active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "user-1",
				"scope":  "read write",
				"iss":    "https://issuer.test",
			})
		case "inactive":
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
		case "malformed":
			w.Write([]byte("{malformed"))
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
		}
	}))
	defer server.Close()

	mkClient := func(id, secret string) *introspect.Client {
		c, err := introspect.New(introspect.Config{
			Endpoint:     server.URL,
			ClientID:     id,
			ClientSecret: secret,
			Timeout:      5 * time.Second,
		})
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		return c
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	t.Run("active token", func(t *testing.T) {
		c := mkClient(clientID, clientSecret)
		resp, err := c.Introspect(ctx, "active")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Active {
			t.Fatalf("expected active true")
		}
		if resp.Sub != "user-1" {
			t.Fatalf("want sub user-1, got %s", resp.Sub)
		}
		if resp.Scope != "read write" {
			t.Fatalf("want scope 'read write', got %q", resp.Scope)
		}
	})

	t.Run("inactive token", func(t *testing.T) {
		c := mkClient(clientID, clientSecret)
		resp, err := c.Introspect(ctx, "inactive")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if err != introspect.ErrTokenInactive {
			t.Fatalf("expected ErrTokenInactive, got %v", err)
		}
		if resp == nil || resp.Active {
			t.Fatalf("expected inactive response body")
		}
	})

	t.Run("wrong credentials", func(t *testing.T) {
		c := mkClient(clientID, "wrong")
		_, err := c.Introspect(ctx, "active")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "status: 401") {
			t.Fatalf("expected 401 error, got %v", err)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		c := mkClient(clientID, clientSecret)
		_, err := c.Introspect(ctx, "malformed")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to parse introspection response") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
