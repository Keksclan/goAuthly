package jwt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/internal/jwk"
)

// AudienceRule mirrors authly.AudienceRule for internal use.
type AudienceRule struct {
	AnyAudience bool
	AnyOf       []string
	AllOf       []string
	Blocklist   []string
}

type Config struct {
	Issuer       string
	Audience     string
	AudienceRule AudienceRule
	AllowedAlgs  []string
}

type Claims struct {
	Subject   string
	Issuer    string
	Audience  []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	Scopes    []string
	RawMap    map[string]any
}

type Validator struct {
	cfg           Config
	keys          jwk.Provider
	allowedAlgSet map[string]struct{}
}

func New(cfg Config, keys jwk.Provider) (*Validator, error) {
	v := &Validator{
		cfg:  cfg,
		keys: keys,
	}
	if len(cfg.AllowedAlgs) > 0 {
		v.allowedAlgSet = make(map[string]struct{}, len(cfg.AllowedAlgs))
		for _, alg := range cfg.AllowedAlgs {
			v.allowedAlgSet[alg] = struct{}{}
		}
	}
	return v, nil
}

func (v *Validator) Validate(ctx context.Context, tokenStr string) (*Claims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in header")
		}

		if v.allowedAlgSet != nil {
			if _, ok := v.allowedAlgSet[t.Method.Alg()]; !ok {
				return nil, fmt.Errorf("unsupported algorithm: %s", t.Method.Alg())
			}
		}

		return v.keys.GetKey(ctx, kid)
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	res := &Claims{
		RawMap: claims,
	}

	if sub, err := claims.GetSubject(); err == nil {
		res.Subject = sub
	}
	if iss, err := claims.GetIssuer(); err == nil {
		res.Issuer = iss
	}
	if aud, err := claims.GetAudience(); err == nil {
		res.Audience = aud
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		res.ExpiresAt = exp.Time
	}
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		res.IssuedAt = iat.Time
	}
	if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil {
		res.NotBefore = nbf.Time
	}

	if scope, ok := claims["scope"].(string); ok {
		res.Scopes = strings.Fields(scope)
	}

	// Manual validation for Issuer and Audience as requested
	if v.cfg.Issuer != "" && res.Issuer != v.cfg.Issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.cfg.Issuer, res.Issuer)
	}

	// Audience validation via AudienceRule.
	if err := v.validateAudience(res.Audience); err != nil {
		return nil, err
	}

	return res, nil
}

// audienceRuleIsZero reports whether the AudienceRule has no configuration.
func audienceRuleIsZero(r AudienceRule) bool {
	return !r.AnyAudience && len(r.AnyOf) == 0 && len(r.AllOf) == 0 && len(r.Blocklist) == 0
}

// validateAudience checks the token audiences against the configured rule.
// It resolves the effective rule from the legacy Audience field when needed.
func (v *Validator) validateAudience(tokenAud []string) error {
	rule := v.cfg.AudienceRule
	if audienceRuleIsZero(rule) {
		// Backwards compatibility: convert legacy Audience string.
		if v.cfg.Audience == "*" {
			rule = AudienceRule{AnyAudience: true}
		} else if v.cfg.Audience != "" {
			rule = AudienceRule{AnyOf: []string{v.cfg.Audience}}
		} else {
			return nil // no audience enforcement
		}
	}

	// Build set for efficient lookup.
	audSet := make(map[string]struct{}, len(tokenAud))
	for _, a := range tokenAud {
		audSet[a] = struct{}{}
	}

	// 1. Blocklist always wins.
	for _, blocked := range rule.Blocklist {
		if _, ok := audSet[blocked]; ok {
			return fmt.Errorf("audience blocked: %s", blocked)
		}
	}

	// 2. Wildcard.
	if rule.AnyAudience {
		return nil
	}

	// 3. AllOf: every value must be present.
	for _, required := range rule.AllOf {
		if _, ok := audSet[required]; !ok {
			return fmt.Errorf("audience not allowed: required audience %q not found", required)
		}
	}

	// 4. AnyOf: at least one must be present.
	if len(rule.AnyOf) > 0 {
		found := false
		for _, allowed := range rule.AnyOf {
			if _, ok := audSet[allowed]; ok {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("audience not allowed: none of %v matched", rule.AnyOf)
		}
	}

	return nil
}
