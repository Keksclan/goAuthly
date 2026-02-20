package tests

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/keksclan/goAuthly/internal/basic"
	"golang.org/x/crypto/bcrypt"
)

// TestVerifyUsers_TimingAttackMitigation verifies that the basic auth verifier
// returns the same error type for both wrong-password and non-existing-user
// scenarios and that no information leaks through different error values.
func TestVerifyUsers_TimingAttackMitigation(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}

	v, err := basic.NewVerifier(basic.Config{
		Enabled: true,
		Users:   map[string]string{"alice": string(hash)},
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	ctx := t.Context()

	// Case 1: existing user, wrong password
	errWrongPass := v.Verify(ctx, "alice", "wrong")
	if errWrongPass == nil {
		t.Fatal("wrong password: expected error, got nil")
	}
	if !errors.Is(errWrongPass, basic.ErrInvalidCredentials) {
		t.Fatalf("wrong password: expected ErrInvalidCredentials, got %v", errWrongPass)
	}

	// Case 2: non-existing user
	errNoUser := v.Verify(ctx, "nonexistent", "whatever")
	if errNoUser == nil {
		t.Fatal("non-existing user: expected error, got nil")
	}
	if !errors.Is(errNoUser, basic.ErrInvalidCredentials) {
		t.Fatalf("non-existing user: expected ErrInvalidCredentials, got %v", errNoUser)
	}

	// Both errors must be identical — no information leakage via error value.
	if errWrongPass.Error() != errNoUser.Error() {
		t.Errorf("error messages differ: wrong-pass=%q, no-user=%q", errWrongPass.Error(), errNoUser.Error())
	}
}

// TestVerifyUsers_NoEarlyReturnBeforeBcrypt statically inspects the source of
// verifyUsers to ensure there is no early return before bcrypt.CompareHashAndPassword
// is called in the !exists branch. This guarantees timing consistency.
func TestVerifyUsers_NoEarlyReturnBeforeBcrypt(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../internal/basic/basic.go", nil, 0)
	if err != nil {
		t.Fatalf("parse basic.go: %v", err)
	}

	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "verifyUsers" {
			return true
		}
		found = true

		// Walk the function body and find the if !exists block.
		for _, stmt := range fn.Body.List {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}
			// Look for the branch that handles user-not-found (!exists).
			unary, ok := ifStmt.Cond.(*ast.UnaryExpr)
			if !ok || unary.Op.String() != "!" {
				continue
			}
			ident, ok := unary.X.(*ast.Ident)
			if !ok || ident.Name != "exists" {
				continue
			}

			// Inside the !exists block, verify CompareHashAndPassword is called
			// before any return statement.
			bcryptCalled := false
			for _, s := range ifStmt.Body.List {
				ast.Inspect(s, func(inner ast.Node) bool {
					call, ok := inner.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if ok && sel.Sel.Name == "CompareHashAndPassword" {
						bcryptCalled = true
					}
					return true
				})
				// Check if this statement is a return — it must come after bcrypt call.
				if _, isRet := s.(*ast.ReturnStmt); isRet && !bcryptCalled {
					t.Error("early return found before bcrypt.CompareHashAndPassword in !exists branch")
				}
			}
			if !bcryptCalled {
				t.Error("bcrypt.CompareHashAndPassword not called in !exists branch")
			}
		}
		return false
	})

	if !found {
		t.Fatal("verifyUsers function not found in basic.go")
	}
}
