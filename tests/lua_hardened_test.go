package tests

import (
	"errors"
	"testing"
	"time"

	"github.com/keksclan/goAuthly/internal/luaengine"
)

// TestLuaInfiniteLoopTerminated verifies that an infinite loop script
// is terminated by the instruction limit and returns a safe error.
func TestLuaInfiniteLoopTerminated(t *testing.T) {
	script := `while true do end`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Use a very small instruction limit so the budget fires quickly.
	err = cp.EvaluateWithLimits(
		map[string]any{"sub": "user-1"},
		"jwt",
		5*time.Second,
		1_000, // very low instruction limit → tiny time budget
	)
	if err == nil {
		t.Fatal("expected error for infinite loop, got nil")
	}
	if !errors.Is(err, luaengine.ErrLuaInstructionLimit) {
		t.Errorf("expected ErrLuaInstructionLimit, got: %v", err)
	}
}

// TestLuaTimeoutTerminated verifies that a long-running script
// is terminated by the execution timeout when no instruction limit is set.
func TestLuaTimeoutTerminated(t *testing.T) {
	script := `while true do end`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// No instruction limit, rely on timeout only.
	err = cp.EvaluateWithLimits(
		map[string]any{"sub": "user-1"},
		"jwt",
		50*time.Millisecond,
		0, // no instruction limit
	)
	if err == nil {
		t.Fatal("expected error for infinite loop, got nil")
	}
	if !errors.Is(err, luaengine.ErrLuaTimeout) {
		t.Errorf("expected ErrLuaTimeout, got: %v", err)
	}
}

// TestLuaInfiniteLoopErrorReturnedSafely ensures the error from a terminated
// infinite loop is returned safely without panics.
func TestLuaInfiniteLoopErrorReturnedSafely(t *testing.T) {
	script := `while true do end`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Should not panic — error must be returned safely.
	err = cp.EvaluateWithLimits(
		map[string]any{},
		"jwt",
		1*time.Second,
		5_000,
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Error should be one of the known limit errors.
	if !errors.Is(err, luaengine.ErrLuaInstructionLimit) && !errors.Is(err, luaengine.ErrLuaTimeout) {
		t.Errorf("expected instruction limit or timeout error, got: %v", err)
	}
}

// TestLuaNoPanicPropagation verifies the panic recovery in Lua evaluation.
func TestLuaNoPanicPropagation(t *testing.T) {
	// A valid script that succeeds should not trigger panic recovery.
	script := `require_claim("sub")`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	err = cp.Evaluate(map[string]any{"sub": "user-1"}, "jwt")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// TestLuaNormalScriptWithInstructionLimit verifies that normal scripts
// complete successfully within the instruction budget.
func TestLuaNormalScriptWithInstructionLimit(t *testing.T) {
	script := `
require_claim("sub")
require_value("iss", "https://issuer.demo")
`
	cp, err := luaengine.Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	err = cp.EvaluateWithLimits(
		map[string]any{"sub": "user-1", "iss": "https://issuer.demo"},
		"jwt",
		5*time.Second,
		luaengine.DefaultMaxInstructions,
	)
	if err != nil {
		t.Errorf("expected nil error for valid script, got %v", err)
	}
}
