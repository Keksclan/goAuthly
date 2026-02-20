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
	var branchFound bool
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
			branchFound = true

			// Walk the entire !exists block (at any depth) to find the position
			// of the first CompareHashAndPassword call and every ReturnStmt.
			// Then assert that no return appears before the bcrypt call.
			var bcryptPos token.Pos
			var returnPositions []token.Pos

			ast.Inspect(ifStmt.Body, func(inner ast.Node) bool {
				switch n := inner.(type) {
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if ok && sel.Sel.Name == "CompareHashAndPassword" && !bcryptPos.IsValid() {
						bcryptPos = n.Pos()
					}
				case *ast.ReturnStmt:
					returnPositions = append(returnPositions, n.Pos())
				}
				return true
			})

			if !bcryptPos.IsValid() {
				t.Error("bcrypt.CompareHashAndPassword not called in !exists branch")
			}
			for _, rp := range returnPositions {
				if rp < bcryptPos {
					t.Errorf("early return at %s before bcrypt.CompareHashAndPassword at %s",
						fset.Position(rp), fset.Position(bcryptPos))
				}
			}
		}
		return false
	})

	if !found {
		t.Fatal("verifyUsers function not found in basic.go")
	}
	if !branchFound {
		t.Fatal("!exists branch not found in verifyUsers; the timing-safe pattern may have been refactored away")
	}
}
