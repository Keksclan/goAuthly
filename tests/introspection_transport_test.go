package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keksclan/goAuthly/internal/oauth/introspect"
)

func TestIntrospectionBodyTransport(t *testing.T) {
	var receivedToken string
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		_ = r.ParseForm()
		receivedToken = r.FormValue("token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1"})
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		TokenTransport: introspect.TokenTransport{
			Kind:  introspect.TokenTransportBody,
			Field: "token",
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx := context.Background()
	resp, err := c.Introspect(ctx, "my-opaque-token")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active")
	}
	if receivedToken != "my-opaque-token" {
		t.Errorf("token in body: want my-opaque-token, got %s", receivedToken)
	}
	if receivedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type: want form-urlencoded, got %s", receivedContentType)
	}
}

func TestIntrospectionCustomBodyField(t *testing.T) {
	var receivedToken string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedToken = r.FormValue("access_token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1"})
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		TokenTransport: introspect.TokenTransport{
			Kind:  introspect.TokenTransportBody,
			Field: "access_token",
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(context.Background(), "tok123")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if receivedToken != "tok123" {
		t.Errorf("token in custom field: want tok123, got %s", receivedToken)
	}
}

func TestIntrospectionHeaderTransport(t *testing.T) {
	var receivedHeader string
	var receivedBodyToken string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Token")
		_ = r.ParseForm()
		receivedBodyToken = r.FormValue("token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1"})
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		TokenTransport: introspect.TokenTransport{
			Kind:   introspect.TokenTransportHeader,
			Header: "X-Token",
			Prefix: "Bearer ",
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(context.Background(), "hdr-token")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if receivedHeader != "Bearer hdr-token" {
		t.Errorf("header value: want 'Bearer hdr-token', got %q", receivedHeader)
	}
	// Token should NOT be in body when transport is header
	if receivedBodyToken != "" {
		t.Errorf("body should be empty for header transport, got %q", receivedBodyToken)
	}
}

func TestIntrospectionBasicAuth(t *testing.T) {
	var receivedUser, receivedPass string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUser, receivedPass, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1"})
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Auth: introspect.ClientAuth{
			Kind:         introspect.ClientAuthBasic,
			ClientID:     "myid",
			ClientSecret: "mysecret",
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(context.Background(), "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if receivedUser != "myid" || receivedPass != "mysecret" {
		t.Errorf("basic auth: want myid/mysecret, got %s/%s", receivedUser, receivedPass)
	}
}

func TestIntrospectionBearerAuth(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1"})
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Auth: introspect.ClientAuth{
			Kind:         introspect.ClientAuthBearer,
			ClientSecret: "my-bearer-token",
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(context.Background(), "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if receivedAuth != "Bearer my-bearer-token" {
		t.Errorf("bearer auth: want 'Bearer my-bearer-token', got %q", receivedAuth)
	}
}

func TestIntrospectionBodyAuth(t *testing.T) {
	var receivedClientID, receivedClientSecret string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedClientID = r.FormValue("client_id")
		receivedClientSecret = r.FormValue("client_secret")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1"})
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Auth: introspect.ClientAuth{
			Kind:         introspect.ClientAuthBody,
			ClientID:     "cid",
			ClientSecret: "csec",
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(context.Background(), "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if receivedClientID != "cid" {
		t.Errorf("body auth client_id: want cid, got %s", receivedClientID)
	}
	if receivedClientSecret != "csec" {
		t.Errorf("body auth client_secret: want csec, got %s", receivedClientSecret)
	}
}

func TestIntrospectionCustomHeaderAuth(t *testing.T) {
	var receivedHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1"})
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Auth: introspect.ClientAuth{
			Kind:        introspect.ClientAuthHeader,
			HeaderName:  "X-Api-Key",
			HeaderValue: "secret-key",
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(context.Background(), "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if receivedHeader != "secret-key" {
		t.Errorf("custom header: want secret-key, got %s", receivedHeader)
	}
}

func TestIntrospectionExtraHeadersAndBody(t *testing.T) {
	var receivedExtraHeader string
	var receivedExtraBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedExtraHeader = r.Header.Get("X-Custom")
		_ = r.ParseForm()
		receivedExtraBody = r.FormValue("hint")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1"})
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint:     server.URL,
		Timeout:      5 * time.Second,
		ExtraHeaders: map[string]string{"X-Custom": "val"},
		ExtraBody:    map[string]string{"hint": "access_token"},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(context.Background(), "tok")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if receivedExtraHeader != "val" {
		t.Errorf("extra header: want val, got %s", receivedExtraHeader)
	}
	if receivedExtraBody != "access_token" {
		t.Errorf("extra body: want access_token, got %s", receivedExtraBody)
	}
}
