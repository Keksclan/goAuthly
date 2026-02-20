package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keksclan/goAuthly/internal/oauth/introspect"
)

func TestIntrospectNoTimeoutWhenZero(t *testing.T) {
	// A server that delays 2s; with Timeout==0 (no timeout) the request should succeed.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  0, // zero → no timeout
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.Introspect(t.Context(), "tok")
	if err != nil {
		t.Fatalf("expected no error with zero timeout (no timeout), got %v", err)
	}
}

func TestIntrospectDefaultTimeoutWhenNegative(t *testing.T) {
	// A server that delays longer than the default 5s timeout.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(6 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  -1 * time.Second, // negative → should default to 5s
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	start := time.Now()
	_, err = c.Introspect(t.Context(), "tok")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// Should have timed out around 5s, not waited the full 6s
	if elapsed < 4*time.Second || elapsed >= 6*time.Second {
		t.Fatalf("expected timeout around 5s, got %v", elapsed)
	}
}

func TestIntrospectRespectsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = c.Introspect(ctx, "tok")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("request did not respect context cancellation (took %v)", elapsed)
	}
}
