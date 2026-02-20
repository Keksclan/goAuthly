package luaengine

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// TestPanicRecovery exercises the defer/recover guard in EvaluateWithLimits.
// It uses the panicHook testing seam to inject a deliberate Go panic and
// asserts the returned error wraps ErrLuaPanic.
func TestPanicRecovery(t *testing.T) {
	script := `require_claim("sub")`
	cp, err := Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	cp.panicHook.Store(func() { panic("deliberate test panic") })

	err = cp.Evaluate(map[string]any{"sub": "user-1"}, "jwt")
	if err == nil {
		t.Fatal("expected ErrLuaPanic error, got nil")
	}
	if !errors.Is(err, ErrLuaPanic) {
		t.Fatalf("expected errors.Is(err, ErrLuaPanic), got: %v", err)
	}
	if !strings.Contains(err.Error(), "deliberate test panic") {
		t.Errorf("error should contain panic message, got: %v", err)
	}
}

// TestInstructionBudgetOverflowCapped verifies that extremely large
// maxInstructions values (which would overflow time.Duration) are capped
// instead of producing a negative/zero budget that instantly cancels evaluation.
func TestInstructionBudgetOverflowCapped(t *testing.T) {
	script := `require_claim("sub")`
	cp, err := Compile(script)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// math.MaxInt would overflow time.Duration(maxInstructions) * instructionBudgetPerUnit.
	// Without the cap this would create a negative duration → immediate cancellation.
	err = cp.EvaluateWithLimits(
		map[string]any{"sub": "user-1"},
		"jwt",
		5*time.Second,
		math.MaxInt,
	)
	if err != nil {
		t.Fatalf("expected nil (script should succeed with capped budget), got: %v", err)
	}
}
