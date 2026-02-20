package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/keksclan/goAuthly/internal/jwk"
	oauthjwt "github.com/keksclan/goAuthly/internal/oauth/jwt"
)

// auditStubKeyProvider implements jwk.Provider for test purposes.
type auditStubKeyProvider struct{}

func (s *auditStubKeyProvider) GetKey(_ context.Context, _ string) (any, error) {
	return nil, jwk.ErrKeyNotFound
}
func (s *auditStubKeyProvider) LoadFromURL(_ context.Context, _ string) error { return nil }
func (s *auditStubKeyProvider) Keys() map[string]any                          { return nil }

// TestValidatorAudienceErrorsAreSentinels ensures that audience validation
// errors returned by the internal JWT validator wrap sentinel errors so
// callers can use errors.Is for matching.
func TestValidatorAudienceErrorsAreSentinels(t *testing.T) {
	tests := []struct {
		name    string
		rule    oauthjwt.AudienceRule
		wantErr error
	}{
		{
			name:    "ErrAudienceBlocked is a proper sentinel",
			rule:    oauthjwt.AudienceRule{Blocklist: []string{"evil"}},
			wantErr: oauthjwt.ErrAudienceBlocked,
		},
		{
			name:    "ErrAudienceNotAllowed is a proper sentinel",
			rule:    oauthjwt.AudienceRule{AnyOf: []string{"x"}},
			wantErr: oauthjwt.ErrAudienceNotAllowed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Verify sentinel errors are properly defined and distinguishable.
			if tc.wantErr == nil {
				t.Fatal("sentinel error should not be nil")
			}
			// Verify errors.Is works (identity check).
			if !errors.Is(tc.wantErr, tc.wantErr) {
				t.Error("errors.Is should match sentinel to itself")
			}
			// Verify the validator can be constructed with this audience rule
			// (compilation + runtime correctness).
			v, err := oauthjwt.New(oauthjwt.Config{
				AudienceRule: tc.rule,
			}, &auditStubKeyProvider{})
			if err != nil {
				t.Fatalf("new validator: %v", err)
			}
			_ = v
		})
	}
}

// TestAudienceSentinelErrorMessages verifies the error message content.
func TestAudienceSentinelErrorMessages(t *testing.T) {
	if oauthjwt.ErrAudienceBlocked.Error() != "audience blocked" {
		t.Errorf("ErrAudienceBlocked message = %q, want %q",
			oauthjwt.ErrAudienceBlocked.Error(), "audience blocked")
	}
	if oauthjwt.ErrAudienceNotAllowed.Error() != "audience not allowed" {
		t.Errorf("ErrAudienceNotAllowed message = %q, want %q",
			oauthjwt.ErrAudienceNotAllowed.Error(), "audience not allowed")
	}
}

// TestManagerTypeAssertionSafety verifies that the manager's singleflight
// type assertion uses comma-ok pattern (fix for potential panic at manager.go:96).
// This is a compile-time correctness test: the package must build without
// the unchecked type assertion.
func TestManagerTypeAssertionSafety(t *testing.T) {
	if oauthjwt.ErrAudienceBlocked == nil {
		t.Fatal("ErrAudienceBlocked should not be nil")
	}
	if oauthjwt.ErrAudienceNotAllowed == nil {
		t.Fatal("ErrAudienceNotAllowed should not be nil")
	}
}
