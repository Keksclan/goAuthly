package jwk

import (
	"context"
	"strings"
	"testing"
	"time"
)

// stubCache is a minimal cache.Cache for testing; it never holds a value.
type stubCache struct{}

func (stubCache) Get(string) (any, bool)                     { return nil, false }
func (stubCache) Set(string, any, int64, time.Duration) bool { return true }
func (stubCache) Del(string)                                 {}

func TestManagerTypeAssertionSafety(t *testing.T) {
	mgr := NewManager(stubCache{}, time.Minute, false)

	// Inject a fetch override that returns a non-jwk.Set value (a plain string)
	// with no error, so the singleflight result triggers the type-assertion branch.
	mgr.fetchOverride = func(_ context.Context, _ string) (any, error) {
		return "not-a-jwk-set", nil
	}

	_, err := mgr.GetKey(t.Context(), "https://example.com/.well-known/jwks.json", "kid-1")
	if err == nil {
		t.Fatal("expected error for non-jwk.Set singleflight result, got nil")
	}

	want := "unexpected singleflight result type"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error should contain %q, got: %v", want, err)
	}

	// Verify the enhanced message includes the dynamic type and context.
	for _, substr := range []string{"string", "jwksURL=", "kid="} {
		if !strings.Contains(err.Error(), substr) {
			t.Errorf("error should contain %q, got: %v", substr, err)
		}
	}
}
