package tests

import (
	"strings"
	"testing"

	"github.com/keksclan/goAuthly/internal/luaengine"
)

func TestLuaClaimsPolicyRequireClaim(t *testing.T) {
	script := `require_claim("sub")`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Should pass when claim exists
	err = cp.Evaluate(map[string]any{"sub": "user-1"}, "jwt")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	// Should fail when claim missing
	err = cp.Evaluate(map[string]any{"iss": "x"}, "jwt")
	if err == nil {
		t.Fatal("expected error for missing claim")
	}
	if !strings.Contains(err.Error(), "required claim missing: sub") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLuaClaimsPolicyRequireValue(t *testing.T) {
	script := `require_value("iss", "https://issuer.demo")`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	err = cp.Evaluate(map[string]any{"iss": "https://issuer.demo"}, "jwt")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	err = cp.Evaluate(map[string]any{"iss": "wrong"}, "jwt")
	if err == nil {
		t.Fatal("expected error for value mismatch")
	}
}

func TestLuaClaimsPolicyConditionalWithOneOf(t *testing.T) {
	// If claim "xy" exists, then claim "x" must exist and be one of {"a","b","c"}
	script := `
if has("xy") then
  require_claim("x")
  require_one_of("x", {"a", "b", "c"})
end
`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// No "xy" claim: should pass regardless
	err = cp.Evaluate(map[string]any{"sub": "u"}, "jwt")
	if err != nil {
		t.Errorf("expected pass without xy: %v", err)
	}

	// "xy" present, "x" present and valid
	err = cp.Evaluate(map[string]any{"xy": "1", "x": "b"}, "jwt")
	if err != nil {
		t.Errorf("expected pass with valid x: %v", err)
	}

	// "xy" present, "x" missing
	err = cp.Evaluate(map[string]any{"xy": "1"}, "opaque")
	if err == nil {
		t.Fatal("expected error when x is missing")
	}
	if !strings.Contains(err.Error(), "required claim missing: x") {
		t.Errorf("unexpected error: %v", err)
	}

	// "xy" present, "x" present but not in allowed set
	err = cp.Evaluate(map[string]any{"xy": "1", "x": "z"}, "jwt")
	if err == nil {
		t.Fatal("expected error when x is not in allowed set")
	}
	if !strings.Contains(err.Error(), "not in allowed set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLuaClaimsPolicyReject(t *testing.T) {
	script := `reject("custom rejection reason")`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	err = cp.Evaluate(map[string]any{"sub": "u"}, "jwt")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), "custom rejection reason") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLuaClaimsPolicyTokenTypeAware(t *testing.T) {
	script := `
if token_type == "opaque" then
  require_claim("scope")
end
`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// JWT: should pass without scope
	err = cp.Evaluate(map[string]any{"sub": "u"}, "jwt")
	if err != nil {
		t.Errorf("expected pass for jwt: %v", err)
	}

	// Opaque without scope: should fail
	err = cp.Evaluate(map[string]any{"sub": "u"}, "opaque")
	if err == nil {
		t.Fatal("expected error for opaque without scope")
	}

	// Opaque with scope: should pass
	err = cp.Evaluate(map[string]any{"sub": "u", "scope": "read"}, "opaque")
	if err != nil {
		t.Errorf("expected pass for opaque with scope: %v", err)
	}
}

func TestLuaClaimsPolicyTypeCheckers(t *testing.T) {
	script := `
if not is_string("name") then
  reject("name must be string")
end
if not is_number("age") then
  reject("age must be number")
end
`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	err = cp.Evaluate(map[string]any{"name": "alice", "age": float64(30)}, "jwt")
	if err != nil {
		t.Errorf("expected pass: %v", err)
	}

	err = cp.Evaluate(map[string]any{"name": 123, "age": float64(30)}, "jwt")
	if err == nil {
		t.Fatal("expected error for non-string name")
	}
}

func TestLuaClaimsPolicyHasAndGet(t *testing.T) {
	script := `
if has("role") then
  local r = get("role")
  if r ~= "admin" then
    reject("must be admin")
  end
end
`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	err = cp.Evaluate(map[string]any{"role": "admin"}, "jwt")
	if err != nil {
		t.Errorf("expected pass: %v", err)
	}

	err = cp.Evaluate(map[string]any{"role": "user"}, "jwt")
	if err == nil {
		t.Fatal("expected rejection for non-admin")
	}

	// No role claim: should pass
	err = cp.Evaluate(map[string]any{"sub": "u"}, "jwt")
	if err != nil {
		t.Errorf("expected pass without role: %v", err)
	}
}

func TestLuaClaimsPolicyCompileError(t *testing.T) {
	_, err := luaengine.Compile("this is not valid lua %%%")
	if err == nil {
		t.Fatal("expected compile error")
	}
}

func TestLuaClaimsPolicyCrossClaimDependency(t *testing.T) {
	// From the issue spec: if has("actor") then require_claim("sub") and require_value("iss", ...)
	script := `
if has("actor") then
  require_claim("sub")
  require_value("iss", "https://issuer.demo")
end
`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// No actor: passes
	err = cp.Evaluate(map[string]any{"sub": "u"}, "jwt")
	if err != nil {
		t.Errorf("expected pass: %v", err)
	}

	// Actor present, sub present, correct iss
	err = cp.Evaluate(map[string]any{
		"actor": map[string]any{"sub": "svc"},
		"sub":   "u",
		"iss":   "https://issuer.demo",
	}, "jwt")
	if err != nil {
		t.Errorf("expected pass: %v", err)
	}

	// Actor present, sub missing
	err = cp.Evaluate(map[string]any{
		"actor": map[string]any{"sub": "svc"},
		"iss":   "https://issuer.demo",
	}, "jwt")
	if err == nil {
		t.Fatal("expected error for missing sub")
	}

	// Actor present, wrong iss
	err = cp.Evaluate(map[string]any{
		"actor": map[string]any{"sub": "svc"},
		"sub":   "u",
		"iss":   "wrong",
	}, "jwt")
	if err == nil {
		t.Fatal("expected error for wrong iss")
	}
}
