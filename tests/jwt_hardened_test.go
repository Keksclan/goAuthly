package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	oauthjwt "github.com/keksclan/goAuthly/internal/oauth/jwt"
)

// staticKeyProvider returns a fixed key regardless of kid.
type staticKeyProvider struct {
	key any
}

func (p *staticKeyProvider) GetKey(_ context.Context, _ string) (any, error) {
	return p.key, nil
}
func (p *staticKeyProvider) LoadFromURL(_ context.Context, _ string) error { return nil }
func (p *staticKeyProvider) Keys() map[string]any                          { return nil }

// hmacKeyProvider returns an HMAC key for any kid.
type hmacKeyProvider struct {
	secret []byte
}

func (p *hmacKeyProvider) GetKey(_ context.Context, _ string) (any, error) {
	return p.secret, nil
}
func (p *hmacKeyProvider) LoadFromURL(_ context.Context, _ string) error { return nil }
func (p *hmacKeyProvider) Keys() map[string]any                          { return nil }

func TestHardenedJWT_InvalidAlgorithm(t *testing.T) {
	// Token signed with HS256, AllowedAlgs only contains RS256 → expect rejection.
	secret := []byte("super-secret-key-for-hmac-256-xx")

	makeToken := func(claims gojwt.MapClaims) string {
		tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
		tok.Header["kid"] = "hmac-key"
		s, err := tok.SignedString(secret)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	tests := []struct {
		name        string
		allowedAlgs []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "HS256 rejected when only RS256 allowed",
			allowedAlgs: []string{"RS256"},
			wantErr:     true,
			errContains: "signing method",
		},
		{
			name:        "HS256 rejected when only ES256 allowed",
			allowedAlgs: []string{"ES256"},
			wantErr:     true,
			errContains: "signing method",
		},
		{
			name:        "HS256 rejected when RS256 and ES256 allowed",
			allowedAlgs: []string{"RS256", "ES256"},
			wantErr:     true,
			errContains: "signing method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &hmacKeyProvider{secret: secret}
			v, err := oauthjwt.New(oauthjwt.Config{
				AllowedAlgs: tt.allowedAlgs,
			}, kp)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			token := makeToken(gojwt.MapClaims{
				"sub": "user-1",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"iat": time.Now().Unix(),
			})

			_, err = v.Validate(t.Context(), token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestHardenedJWT_MissingKid_JWKSMode(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	makeTokenNoKid := func(claims gojwt.MapClaims) string {
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
		// Explicitly do NOT set kid header.
		delete(tok.Header, "kid")
		s, err := tok.SignedString(privKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	makeTokenEmptyKid := func(claims gojwt.MapClaims) string {
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
		tok.Header["kid"] = ""
		s, err := tok.SignedString(privKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	baseClaims := gojwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}

	tests := []struct {
		name        string
		token       string
		jwksEnabled bool
		wantErr     bool
		errContains string
	}{
		{
			name:        "no kid with JWKS enabled",
			token:       makeTokenNoKid(baseClaims),
			jwksEnabled: true,
			wantErr:     true,
			errContains: "kid",
		},
		{
			name:        "empty kid with JWKS enabled",
			token:       makeTokenEmptyKid(baseClaims),
			jwksEnabled: true,
			wantErr:     true,
			errContains: "kid",
		},
		{
			name:        "no kid without JWKS succeeds (kid only required for JWKS)",
			token:       makeTokenNoKid(baseClaims),
			jwksEnabled: false,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &staticKeyProvider{key: &privKey.PublicKey}
			v, err := oauthjwt.New(oauthjwt.Config{
				AllowedAlgs: []string{"RS256"},
				JWKSEnabled: tt.jwksEnabled,
			}, kp)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, err = v.Validate(t.Context(), tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestHardenedJWT_WrongIssuer(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "iss-test-key"

	makeToken := func(claims gojwt.MapClaims) string {
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(privKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	tests := []struct {
		name          string
		configuredIss string
		tokenIss      string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "issuer mismatch",
			configuredIss: "https://auth.example.com",
			tokenIss:      "https://evil.example.com",
			wantErr:       true,
			errContains:   "issuer",
		},
		{
			name:          "empty token issuer when configured",
			configuredIss: "https://auth.example.com",
			tokenIss:      "",
			wantErr:       true,
			errContains:   "issuer",
		},
		{
			name:          "matching issuer passes",
			configuredIss: "https://auth.example.com",
			tokenIss:      "https://auth.example.com",
			wantErr:       false,
		},
		{
			name:          "no configured issuer skips check",
			configuredIss: "",
			tokenIss:      "https://anything.example.com",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &mockKeyProvider{keys: map[string]any{kid: &privKey.PublicKey}}
			v, err := oauthjwt.New(oauthjwt.Config{
				Issuer:      tt.configuredIss,
				AllowedAlgs: []string{"RS256"},
			}, kp)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			claims := gojwt.MapClaims{
				"sub": "user-1",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"iat": time.Now().Unix(),
			}
			if tt.tokenIss != "" {
				claims["iss"] = tt.tokenIss
			}

			token := makeToken(claims)
			_, err = v.Validate(t.Context(), token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
			// Ensure error does not leak actual issuer values.
			if tt.wantErr && err != nil {
				if strings.Contains(err.Error(), tt.tokenIss) && tt.tokenIss != "" {
					t.Errorf("error leaks token issuer value: %v", err)
				}
			}
		})
	}
}

func TestHardenedJWT_ExpiredToken(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "exp-test-key"

	makeToken := func(claims gojwt.MapClaims) string {
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(privKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	tests := []struct {
		name        string
		exp         time.Time
		clockSkew   time.Duration
		wantErr     bool
		errContains string
	}{
		{
			name:        "expired beyond default skew",
			exp:         time.Now().Add(-2 * time.Minute),
			clockSkew:   0, // uses default 30s
			wantErr:     true,
			errContains: "expired",
		},
		{
			name:        "expired beyond custom skew",
			exp:         time.Now().Add(-10 * time.Second),
			clockSkew:   5 * time.Second,
			wantErr:     true,
			errContains: "expired",
		},
		{
			name:      "expired within skew is accepted",
			exp:       time.Now().Add(-20 * time.Second),
			clockSkew: 60 * time.Second,
			wantErr:   false,
		},
		{
			name:      "not expired",
			exp:       time.Now().Add(5 * time.Minute),
			clockSkew: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &mockKeyProvider{keys: map[string]any{kid: &privKey.PublicKey}}
			v, err := oauthjwt.New(oauthjwt.Config{
				AllowedAlgs: []string{"RS256"},
				ClockSkew:   tt.clockSkew,
			}, kp)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			token := makeToken(gojwt.MapClaims{
				"sub": "user-1",
				"exp": tt.exp.Unix(),
				"iat": time.Now().Add(-10 * time.Minute).Unix(),
			})

			_, err = v.Validate(t.Context(), token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestHardenedJWT_NotYetValid(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "nbf-test-key"

	makeToken := func(claims gojwt.MapClaims) string {
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(privKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	tests := []struct {
		name        string
		nbf         time.Time
		clockSkew   time.Duration
		wantErr     bool
		errContains string
	}{
		{
			name:        "nbf in future beyond default skew",
			nbf:         time.Now().Add(2 * time.Minute),
			clockSkew:   0,
			wantErr:     true,
			errContains: "not valid yet",
		},
		{
			name:        "nbf in future beyond custom skew",
			nbf:         time.Now().Add(20 * time.Second),
			clockSkew:   5 * time.Second,
			wantErr:     true,
			errContains: "not valid yet",
		},
		{
			name:      "nbf in future within skew is accepted",
			nbf:       time.Now().Add(10 * time.Second),
			clockSkew: 60 * time.Second,
			wantErr:   false,
		},
		{
			name:      "nbf in past is accepted",
			nbf:       time.Now().Add(-5 * time.Minute),
			clockSkew: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &mockKeyProvider{keys: map[string]any{kid: &privKey.PublicKey}}
			v, err := oauthjwt.New(oauthjwt.Config{
				AllowedAlgs: []string{"RS256"},
				ClockSkew:   tt.clockSkew,
			}, kp)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			token := makeToken(gojwt.MapClaims{
				"sub": "user-1",
				"exp": time.Now().Add(10 * time.Minute).Unix(),
				"nbf": tt.nbf.Unix(),
				"iat": time.Now().Add(-1 * time.Minute).Unix(),
			})

			_, err = v.Validate(t.Context(), token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestHardenedJWT_IssuedInFuture(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "iat-test-key"

	makeToken := func(claims gojwt.MapClaims) string {
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(privKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	tests := []struct {
		name        string
		iat         time.Time
		clockSkew   time.Duration
		wantErr     bool
		errContains string
	}{
		{
			name:        "iat far in future beyond default skew",
			iat:         time.Now().Add(5 * time.Minute),
			clockSkew:   30 * time.Second,
			wantErr:     true,
			errContains: "issued in the future",
		},
		{
			name:      "iat slightly in future within default skew",
			iat:       time.Now().Add(10 * time.Second),
			clockSkew: 30 * time.Second, // previously defaulted internally; now must be explicit
			wantErr:   false,
		},
		{
			name:      "iat in past is fine",
			iat:       time.Now().Add(-5 * time.Minute),
			clockSkew: 30 * time.Second,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &mockKeyProvider{keys: map[string]any{kid: &privKey.PublicKey}}
			v, err := oauthjwt.New(oauthjwt.Config{
				AllowedAlgs: []string{"RS256"},
				ClockSkew:   tt.clockSkew,
			}, kp)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			token := makeToken(gojwt.MapClaims{
				"sub": "user-1",
				"exp": time.Now().Add(10 * time.Minute).Unix(),
				"iat": tt.iat.Unix(),
			})

			_, err = v.Validate(t.Context(), token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestHardenedJWT_AudienceAllowlistBlocklist(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "aud-test-key"

	makeToken := func(aud any) string {
		claims := gojwt.MapClaims{
			"sub": "user-1",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
		}
		if aud != nil {
			claims["aud"] = aud
		}
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(privKey)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return s
	}

	tests := []struct {
		name        string
		audRule     oauthjwt.AudienceRule
		tokenAud    any
		wantErr     bool
		errContains string
	}{
		{
			name:        "blocklist wins over allowlist",
			audRule:     oauthjwt.AudienceRule{AnyOf: []string{"api", "blocked-svc"}, Blocklist: []string{"blocked-svc"}},
			tokenAud:    "blocked-svc",
			wantErr:     true,
			errContains: "blocked",
		},
		{
			name:     "allowlist match passes",
			audRule:  oauthjwt.AudienceRule{AnyOf: []string{"api", "web"}},
			tokenAud: "api",
			wantErr:  false,
		},
		{
			name:        "allowlist no match rejects",
			audRule:     oauthjwt.AudienceRule{AnyOf: []string{"api", "web"}},
			tokenAud:    "mobile",
			wantErr:     true,
			errContains: "audience not allowed",
		},
		{
			name:     "empty allowlist skips check",
			audRule:  oauthjwt.AudienceRule{},
			tokenAud: "anything",
			wantErr:  false,
		},
		{
			name:        "blocklist rejects even with wildcard",
			audRule:     oauthjwt.AudienceRule{AnyAudience: true, Blocklist: []string{"evil"}},
			tokenAud:    "evil",
			wantErr:     true,
			errContains: "blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &mockKeyProvider{keys: map[string]any{kid: &privKey.PublicKey}}
			v, err := oauthjwt.New(oauthjwt.Config{
				AllowedAlgs:  []string{"RS256"},
				AudienceRule: tt.audRule,
			}, kp)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			token := makeToken(tt.tokenAud)
			_, err = v.Validate(t.Context(), token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestHardenedJWT_AlgorithmConfusion(t *testing.T) {
	// Verify that an attacker cannot use ECDSA when only RSA is allowed.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})
	tok.Header["kid"] = "ec-key"
	tokenStr, err := tok.SignedString(ecKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	kp := &staticKeyProvider{key: &ecKey.PublicKey}
	v, err := oauthjwt.New(oauthjwt.Config{
		AllowedAlgs: []string{"RS256"},
	}, kp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = v.Validate(t.Context(), tokenStr)
	if err == nil {
		t.Fatal("expected rejection for algorithm confusion, got nil")
	}
	if !strings.Contains(err.Error(), "signing method") {
		t.Errorf("error %q does not indicate algorithm rejection", err.Error())
	}
}

func TestHardenedJWT_NoneAlgorithmRejected(t *testing.T) {
	// Manually craft a "none" algorithm token.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"sub":"admin","exp":%d,"iat":%d}`,
		time.Now().Add(5*time.Minute).Unix(),
		time.Now().Unix(),
	)))
	tokenStr := header + "." + payload + "."

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kp := &staticKeyProvider{key: &privKey.PublicKey}
	v, err := oauthjwt.New(oauthjwt.Config{
		AllowedAlgs: []string{"RS256"},
	}, kp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = v.Validate(t.Context(), tokenStr)
	if err == nil {
		t.Fatal("expected rejection for 'none' algorithm, got nil")
	}
}

// Ensure errors don't leak sensitive token/claim information.
func TestHardenedJWT_ErrorsDoNotLeakClaims(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "leak-test-key"
	secretSub := "super-secret-user-id-12345"

	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{
		"sub": secretSub,
		"iss": "https://evil.example.com",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})
	tok.Header["kid"] = kid
	tokenStr, err := tok.SignedString(privKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	kp := &mockKeyProvider{keys: map[string]any{kid: &privKey.PublicKey}}
	v, err := oauthjwt.New(oauthjwt.Config{
		Issuer:      "https://auth.example.com",
		AllowedAlgs: []string{"RS256"},
	}, kp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = v.Validate(t.Context(), tokenStr)
	if err == nil {
		t.Fatal("expected error")
	}

	errStr := err.Error()
	if strings.Contains(errStr, secretSub) {
		t.Errorf("error leaks subject: %s", errStr)
	}
	if strings.Contains(errStr, "evil.example.com") {
		t.Errorf("error leaks token issuer: %s", errStr)
	}
}
