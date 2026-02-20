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

func TestIntrospectDefaultTimeoutWhenZero(t *testing.T) {
	// A server that delays longer than the default 5s timeout.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(6 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	c, err := introspect.New(introspect.Config{
		Endpoint: server.URL,
		Timeout:  0, // zero → should default to 5s
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	start := time.Now()
	_, err = c.Introspect(context.Background(), "tok")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// Should have timed out around 5s, not waited the full 6s
	if elapsed >= 6*time.Second {
		t.Fatalf("request waited too long (%v), timeout was not enforced", elapsed)
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
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", ctx.Err())
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("request did not respect context cancellation (took %v)", elapsed)
	}
}
