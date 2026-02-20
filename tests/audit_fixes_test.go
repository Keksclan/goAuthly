package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/authly"
	oauthjwt "github.com/keksclan/goAuthly/internal/oauth/jwt"
)

// TestValidatorAudienceErrorsAreSentinels ensures that audience validation
// errors returned by the internal JWT validator wrap sentinel errors so
// callers can use errors.Is for matching.
func TestValidatorAudienceErrorsAreSentinels(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pubKey := &privKey.PublicKey
	kid := "audit-key"

	kp := &mockKeyProvider{keys: map[string]any{kid: pubKey}}

	signToken := func(t *testing.T, aud any) string {
		t.Helper()
		claims := gojwt.MapClaims{
			"iss": "https://issuer.test",
			"sub": "user-1",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		if aud != nil {
			claims["aud"] = aud
		}
		token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		s, err := token.SignedString(privKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	tests := []struct {
		name    string
		rule    oauthjwt.AudienceRule
		aud     any // audience claim value for the token
		wantErr error
	}{
		{
			name:    "blocked audience wraps ErrAudienceBlocked",
			rule:    oauthjwt.AudienceRule{AnyAudience: true, Blocklist: []string{"evil"}},
			aud:     []string{"evil"},
			wantErr: authly.ErrAudienceBlocked,
		},
		{
			name:    "no matching anyof wraps ErrAudienceNotAllowed",
			rule:    oauthjwt.AudienceRule{AnyOf: []string{"allowed-api"}},
			aud:     []string{"other-api"},
			wantErr: authly.ErrAudienceNotAllowed,
		},
		{
			name:    "missing allof wraps ErrAudienceNotAllowed",
			rule:    oauthjwt.AudienceRule{AllOf: []string{"api", "tenant"}},
			aud:     []string{"api"},
			wantErr: authly.ErrAudienceNotAllowed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := oauthjwt.New(oauthjwt.Config{
				AudienceRule: tc.rule,
			}, kp)
			if err != nil {
				t.Fatalf("new validator: %v", err)
			}

			tokenStr := signToken(t, tc.aud)
			_, vErr := v.Validate(t.Context(), tokenStr)
			if vErr == nil {
				t.Fatalf("expected error wrapping %v, got nil", tc.wantErr)
			}
			if !errors.Is(vErr, tc.wantErr) {
				t.Fatalf("expected errors.Is(%v, %v) = true, got false; actual error: %v",
					vErr, tc.wantErr, vErr)
			}
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
