package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	oauthjwt "github.com/keksclan/goAuthly/internal/oauth/jwt"
)

type mockKeyProvider struct {
	keys map[string]any
}

func (m *mockKeyProvider) GetKey(ctx context.Context, kid string) (any, error) {
	k, ok := m.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return k, nil
}

func (m *mockKeyProvider) LoadFromURL(ctx context.Context, url string) error { return nil }

func TestJWTValidator(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &privKey.PublicKey
	kid := "test-key"
	issuer := "https://issuer.test"
	audience := "api-service"

	kp := &mockKeyProvider{keys: map[string]any{kid: pubKey}}

	createToken := func(claims gojwt.MapClaims, signingKey any, method gojwt.SigningMethod, keyID string) string {
		token := gojwt.NewWithClaims(method, claims)
		token.Header["kid"] = keyID
		s, _ := token.SignedString(signingKey)
		return s
	}

	tests := []struct {
		name        string
		token       string
		config      oauthjwt.Config
		wantErr     bool
		errContains string
		checkClaims func(*testing.T, *oauthjwt.Claims)
	}{
		{
			name: "Valid token",
			token: createToken(gojwt.MapClaims{
				"iss":   issuer,
				"aud":   audience,
				"sub":   "user-123",
				"exp":   time.Now().Add(5 * time.Minute).Unix(),
				"scope": "read write",
			}, privKey, gojwt.SigningMethodRS256, kid),
			config:  oauthjwt.Config{Issuer: issuer, Audience: audience},
			wantErr: false,
			checkClaims: func(t *testing.T, c *oauthjwt.Claims) {
				if c.Subject != "user-123" {
					t.Errorf("expected sub user-123, got %s", c.Subject)
				}
				expectedScopes := []string{"read", "write"}
				if len(c.Scopes) != 2 {
					t.Errorf("expected 2 scopes, got %d", len(c.Scopes))
				}
				for i, s := range expectedScopes {
					if c.Scopes[i] != s {
						t.Errorf("expected scope %s, got %s", s, c.Scopes[i])
					}
				}
			},
		},
		{
			name: "Wrong audience",
			token: createToken(gojwt.MapClaims{
				"iss": issuer,
				"aud": "wrong-audience",
				"sub": "user-123",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			}, privKey, gojwt.SigningMethodRS256, kid),
			config:      oauthjwt.Config{Issuer: issuer, Audience: audience},
			wantErr:     true,
			errContains: "audience not allowed",
		},
		{
			name: "Wrong issuer",
			token: createToken(gojwt.MapClaims{
				"iss": "https://wrong.issuer",
				"aud": audience,
				"sub": "user-123",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			}, privKey, gojwt.SigningMethodRS256, kid),
			config:      oauthjwt.Config{Issuer: issuer, Audience: audience},
			wantErr:     true,
			errContains: "invalid issuer",
		},
		{
			name: "Expired token",
			token: createToken(gojwt.MapClaims{
				"iss": issuer,
				"aud": audience,
				"sub": "user-123",
				"exp": time.Now().Add(-5 * time.Minute).Unix(),
			}, privKey, gojwt.SigningMethodRS256, kid),
			config:      oauthjwt.Config{Issuer: issuer, Audience: audience},
			wantErr:     true,
			errContains: "expired",
		},
		{
			name: "Invalid signature",
			token: createToken(gojwt.MapClaims{
				"iss": issuer,
				"aud": audience,
				"sub": "user-123",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			}, privKey, gojwt.SigningMethodRS256, kid) + "corrupt",
			config:      oauthjwt.Config{Issuer: issuer, Audience: audience},
			wantErr:     true,
			errContains: "token validation failed",
		},
		{
			name: "Unsupported algorithm",
			token: createToken(gojwt.MapClaims{
				"iss": issuer,
				"aud": audience,
				"sub": "user-123",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			}, privKey, gojwt.SigningMethodRS256, kid),
			config:      oauthjwt.Config{Issuer: issuer, Audience: audience, AllowedAlgs: []string{"ES256"}},
			wantErr:     true,
			errContains: "unsupported algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := oauthjwt.New(tt.config, kp)
			claims, err := v.Validate(context.Background(), tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errContains != "" && (err == nil || !strings.Contains(err.Error(), tt.errContains)) {
				t.Errorf("error %v does not contain %s", err, tt.errContains)
			}
			if !tt.wantErr && tt.checkClaims != nil {
				tt.checkClaims(t, claims)
			}
		})
	}
}
