package authly

import (
	"errors"
	"time"
)

type AuthMode string

const (
	AuthModeOAuth2 AuthMode = "oauth2"
	AuthModeBasic  AuthMode = "basic"
)

type OAuth2Mode string

const (
	OAuth2JWTOnly      OAuth2Mode = "jwt_only"
	OAuth2OpaqueOnly   OAuth2Mode = "opaque_only"
	OAuth2JWTAndOpaque OAuth2Mode = "jwt_and_opaque"
)

type Config struct {
	Mode     AuthMode
	OAuth2   OAuth2Config
	Policies Policies
}

type OAuth2Config struct {
	Mode OAuth2Mode

	Issuer      string
	Audience    string
	AllowedAlgs []string

	JWKSURL        string
	JWKSCacheTTL   time.Duration
	AllowStaleJWKS bool

	Introspection         IntrospectionConfig
	IntrospectionCacheTTL time.Duration
}

type IntrospectionConfig struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	Timeout      time.Duration
}

type Policies struct {
	TokenClaims ClaimPolicy
	Actor       ActorPolicy
}

func (c *Config) setDefaults() {
	if c.Mode == "" {
		c.Mode = AuthModeOAuth2
	}
	if c.OAuth2.Mode == "" {
		c.OAuth2.Mode = OAuth2JWTAndOpaque
	}
	if c.OAuth2.JWKSCacheTTL == 0 {
		c.OAuth2.JWKSCacheTTL = 15 * time.Minute
	}
	if c.OAuth2.Introspection.Timeout == 0 {
		c.OAuth2.Introspection.Timeout = 5 * time.Second
	}
	if c.OAuth2.IntrospectionCacheTTL == 0 {
		c.OAuth2.IntrospectionCacheTTL = 30 * time.Second
	}
	// Policies defaults are zero-values (permit all), Actor disabled by default
	if c.Policies.Actor.ActorSubjectKey == "" {
		c.Policies.Actor.ActorSubjectKey = "sub"
	}
}

func (c Config) Validate() error {
	if c.Mode == AuthModeBasic {
		return ErrUnsupportedMode
	}
	if c.Mode != AuthModeOAuth2 {
		return errors.New("unsupported or empty mode")
	}
	switch c.OAuth2.Mode {
	case OAuth2JWTOnly, OAuth2OpaqueOnly, OAuth2JWTAndOpaque:
	default:
		return errors.New("unsupported oauth2 mode")
	}
	// For JWT modes, JWKSURL must be set
	if (c.OAuth2.Mode == OAuth2JWTOnly || c.OAuth2.Mode == OAuth2JWTAndOpaque) && c.OAuth2.JWKSURL == "" {
		return errors.New("oauth2.jwks_url is required for JWT modes")
	}
	// For opaque modes, introspection endpoint must be set
	if (c.OAuth2.Mode == OAuth2OpaqueOnly || c.OAuth2.Mode == OAuth2JWTAndOpaque) && c.OAuth2.Introspection.Endpoint == "" {
		return errors.New("oauth2.introspection.endpoint is required for opaque modes")
	}
	return nil
}
