package core

import (
	"context"

	"github.com/keksclan/goAuthly/internal/oauth/introspect"
	"github.com/keksclan/goAuthly/internal/oauth/jwt"
)

type UnifiedVerifier struct {
	jwtValidator        *jwt.Validator
	introspectionClient *introspect.Client
}

func NewUnifiedVerifier(jv *jwt.Validator, ic *introspect.Client) *UnifiedVerifier {
	return &UnifiedVerifier{
		jwtValidator:        jv,
		introspectionClient: ic,
	}
}

func (u *UnifiedVerifier) ValidateJWT(ctx context.Context, token string) (*jwt.Claims, error) {
	return u.jwtValidator.Validate(ctx, token)
}

func (u *UnifiedVerifier) IntrospectOpaque(ctx context.Context, token string) (*introspect.IntrospectionResponse, error) {
	return u.introspectionClient.Introspect(ctx, token)
}
