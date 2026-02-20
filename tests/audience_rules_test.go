package tests

import (
	"errors"
	"testing"

	"github.com/keksclan/goAuthly/authly"
)

func TestAudienceRuleValidate(t *testing.T) {
	tests := []struct {
		name     string
		rule     authly.AudienceRule
		tokenAud []string
		wantErr  error
	}{
		// --- Wildcard ---
		{
			name:     "wildcard accepts any audience",
			rule:     authly.AudienceRule{AnyAudience: true},
			tokenAud: []string{"anything", "goes"},
		},
		{
			name:     "wildcard accepts empty audience",
			rule:     authly.AudienceRule{AnyAudience: true},
			tokenAud: []string{},
		},
		{
			name:     "wildcard still blocks blocklisted audience",
			rule:     authly.AudienceRule{AnyAudience: true, Blocklist: []string{"internal-admin"}},
			tokenAud: []string{"api", "internal-admin"},
			wantErr:  authly.ErrAudienceBlocked,
		},
		{
			name:     "wildcard accepts when blocklist does not match",
			rule:     authly.AudienceRule{AnyAudience: true, Blocklist: []string{"internal-admin"}},
			tokenAud: []string{"api", "public"},
		},

		// --- AnyOf (OR) ---
		{
			name:     "anyof matches first",
			rule:     authly.AudienceRule{AnyOf: []string{"api-a", "api-b"}},
			tokenAud: []string{"api-a"},
		},
		{
			name:     "anyof matches second",
			rule:     authly.AudienceRule{AnyOf: []string{"api-a", "api-b"}},
			tokenAud: []string{"api-b"},
		},
		{
			name:     "anyof matches when token has multiple",
			rule:     authly.AudienceRule{AnyOf: []string{"api-a", "api-b"}},
			tokenAud: []string{"other", "api-b"},
		},
		{
			name:     "anyof rejects when none match",
			rule:     authly.AudienceRule{AnyOf: []string{"api-a", "api-b"}},
			tokenAud: []string{"api-c"},
			wantErr:  authly.ErrAudienceNotAllowed,
		},
		{
			name:     "anyof rejects empty token aud",
			rule:     authly.AudienceRule{AnyOf: []string{"api-a"}},
			tokenAud: []string{},
			wantErr:  authly.ErrAudienceNotAllowed,
		},

		// --- AllOf (AND) ---
		{
			name:     "allof requires all present",
			rule:     authly.AudienceRule{AllOf: []string{"api", "tenant:123"}},
			tokenAud: []string{"api", "tenant:123"},
		},
		{
			name:     "allof accepts superset",
			rule:     authly.AudienceRule{AllOf: []string{"api", "tenant:123"}},
			tokenAud: []string{"api", "tenant:123", "extra"},
		},
		{
			name:     "allof rejects when one missing",
			rule:     authly.AudienceRule{AllOf: []string{"api", "tenant:123"}},
			tokenAud: []string{"api"},
			wantErr:  authly.ErrAudienceNotAllowed,
		},
		{
			name:     "allof rejects empty token aud",
			rule:     authly.AudienceRule{AllOf: []string{"api"}},
			tokenAud: []string{},
			wantErr:  authly.ErrAudienceNotAllowed,
		},

		// --- Combined AnyOf + AllOf ---
		{
			name:     "allof and anyof both satisfied",
			rule:     authly.AudienceRule{AllOf: []string{"api"}, AnyOf: []string{"v1", "v2"}},
			tokenAud: []string{"api", "v1"},
		},
		{
			name:     "allof satisfied but anyof not",
			rule:     authly.AudienceRule{AllOf: []string{"api"}, AnyOf: []string{"v1", "v2"}},
			tokenAud: []string{"api", "v3"},
			wantErr:  authly.ErrAudienceNotAllowed,
		},
		{
			name:     "anyof satisfied but allof not",
			rule:     authly.AudienceRule{AllOf: []string{"api", "tenant"}, AnyOf: []string{"v1"}},
			tokenAud: []string{"v1"},
			wantErr:  authly.ErrAudienceNotAllowed,
		},

		// --- Blocklist precedence ---
		{
			name:     "blocklist wins over anyof",
			rule:     authly.AudienceRule{AnyOf: []string{"api-a", "api-b-beta"}, Blocklist: []string{"api-b-beta"}},
			tokenAud: []string{"api-b-beta"},
			wantErr:  authly.ErrAudienceBlocked,
		},
		{
			name:     "blocklist wins over allof",
			rule:     authly.AudienceRule{AllOf: []string{"api", "admin"}, Blocklist: []string{"admin"}},
			tokenAud: []string{"api", "admin"},
			wantErr:  authly.ErrAudienceBlocked,
		},
		{
			name:     "blocklist does not match, allow rules pass",
			rule:     authly.AudienceRule{AnyOf: []string{"api-a", "api-b"}, Blocklist: []string{"api-b-beta"}},
			tokenAud: []string{"api-a"},
		},

		// --- No rules => accept ---
		{
			name:     "empty rule accepts anything",
			rule:     authly.AudienceRule{},
			tokenAud: []string{"whatever"},
		},
		{
			name:     "empty rule accepts empty aud",
			rule:     authly.AudienceRule{},
			tokenAud: []string{},
		},

		// --- aud as single string (simulated as single-element slice) ---
		{
			name:     "single string aud matches anyof",
			rule:     authly.AudienceRule{AnyOf: []string{"my-api"}},
			tokenAud: []string{"my-api"},
		},
		{
			name:     "single string aud does not match anyof",
			rule:     authly.AudienceRule{AnyOf: []string{"my-api"}},
			tokenAud: []string{"other-api"},
			wantErr:  authly.ErrAudienceNotAllowed,
		},

		// --- Complex scenario: accept any except internal-admin ---
		{
			name:     "accept any except internal-admin: allowed",
			rule:     authly.AudienceRule{AnyAudience: true, Blocklist: []string{"internal-admin"}},
			tokenAud: []string{"public-api"},
		},
		{
			name:     "accept any except internal-admin: blocked",
			rule:     authly.AudienceRule{AnyAudience: true, Blocklist: []string{"internal-admin"}},
			tokenAud: []string{"internal-admin"},
			wantErr:  authly.ErrAudienceBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate(tt.tokenAud)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestEffectiveAudienceRule(t *testing.T) {
	t.Run("legacy audience string converts to AnyOf", func(t *testing.T) {
		cfg := authly.OAuth2Config{Audience: "my-api"}
		rule := authly.EffectiveAudienceRule(cfg)
		if rule.AnyAudience {
			t.Fatal("expected AnyAudience=false")
		}
		if len(rule.AnyOf) != 1 || rule.AnyOf[0] != "my-api" {
			t.Fatalf("expected AnyOf=[my-api], got %v", rule.AnyOf)
		}
	})

	t.Run("legacy wildcard converts to AnyAudience", func(t *testing.T) {
		cfg := authly.OAuth2Config{Audience: "*"}
		rule := authly.EffectiveAudienceRule(cfg)
		if !rule.AnyAudience {
			t.Fatal("expected AnyAudience=true")
		}
	})

	t.Run("empty audience means no enforcement", func(t *testing.T) {
		cfg := authly.OAuth2Config{}
		rule := authly.EffectiveAudienceRule(cfg)
		if rule.AnyAudience || len(rule.AnyOf) > 0 || len(rule.AllOf) > 0 || len(rule.Blocklist) > 0 {
			t.Fatalf("expected zero rule, got %+v", rule)
		}
	})

	t.Run("explicit AudienceRule overrides legacy string", func(t *testing.T) {
		cfg := authly.OAuth2Config{
			Audience:     "old-api",
			AudienceRule: authly.AudienceRule{AllOf: []string{"new-api"}},
		}
		rule := authly.EffectiveAudienceRule(cfg)
		if len(rule.AllOf) != 1 || rule.AllOf[0] != "new-api" {
			t.Fatalf("expected AllOf=[new-api], got %+v", rule)
		}
		if len(rule.AnyOf) > 0 {
			t.Fatalf("expected empty AnyOf, got %v", rule.AnyOf)
		}
	})
}
