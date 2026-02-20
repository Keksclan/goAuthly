package jwt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/internal/jwk"
)

type Config struct {
	Issuer      string
	Audience    string
	AllowedAlgs []string
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

	if v.cfg.Audience != "" {
		found := false
		for _, a := range res.Audience {
			if a == v.cfg.Audience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid audience: expected %s", v.cfg.Audience)
		}
	}

	return res, nil
}
