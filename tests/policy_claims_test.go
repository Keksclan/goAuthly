package tests

import (
	"testing"

	"github.com/keksclan/goAuthly/authly"
)

func TestClaimPolicy_Basics(t *testing.T) {
	claims := map[string]any{
		"sub":    "u1",
		"iss":    "i",
		"roles":  []any{"a", "b"},
		"active": true,
		"n":      3,
	}

	// Required
	p := authly.ClaimPolicy{Required: []string{"sub", "iss", "aud"}}
	if err := p.Validate(claims); err == nil || err.Error() == "" {
		t.Fatalf("expected missing claim error")
	}

	// Denylist
	p = authly.ClaimPolicy{Denylist: []string{"active"}}
	if err := p.Validate(claims); err == nil || err.Error() == "" {
		t.Fatalf("expected forbidden claim error")
	}

	// Allowlist unknown should fail
	p = authly.ClaimPolicy{Allowlist: []string{"sub", "iss"}}
	if err := p.Validate(claims); err == nil || err.Error() == "" {
		t.Fatalf("expected unknown claim not allowed")
	}

	// Enforced values string and array
	p = authly.ClaimPolicy{EnforcedValues: map[string][]any{"iss": {"i"}, "roles": {"b"}}}
	if err := p.Validate(claims); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Enforced wrong value
	p = authly.ClaimPolicy{EnforcedValues: map[string][]any{"n": {4.0}}}
	if err := p.Validate(claims); err == nil {
		t.Fatalf("expected enforced value error")
	}
}
