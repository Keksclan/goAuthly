package authly

import (
	"errors"
	"time"
)

// AuthMode selects the top-level authentication mode.
//
// Security: Only OAuth2 is currently supported. Basic mode is reserved
// for future work and is rejected by validation.
type AuthMode string

// Supported AuthMode values.
const (
	// AuthModeOAuth2 enables OAuth 2.0 style verification (JWT and/or opaque introspection).
	AuthModeOAuth2 AuthMode = "oauth2"
	// AuthModeBasic is not supported by this library and will be rejected.
	AuthModeBasic AuthMode = "basic"
)

// OAuth2Mode specifies which OAuth2 token types are accepted.
type OAuth2Mode string

// Supported OAuth2Mode values.
const (
	// OAuth2JWTOnly accepts only JWT tokens.
	OAuth2JWTOnly OAuth2Mode = "jwt_only"
	// OAuth2OpaqueOnly accepts only opaque tokens via introspection.
	OAuth2OpaqueOnly OAuth2Mode = "opaque_only"
	// OAuth2JWTAndOpaque accepts both JWT and opaque tokens.
	OAuth2JWTAndOpaque OAuth2Mode = "jwt_and_opaque"
)

// Config controls Engine behavior.
//
// Concurrency: Config is immutable after passing to New; do not mutate concurrently.
// Security: Set Issuer/Audience and algorithms to enforce constraints.
type Config struct {
	Mode     AuthMode
	OAuth2   OAuth2Config
	Policies Policies
}

// OAuth2Config configures OAuth2 verification.
//
// JWKS caching is controlled by JWKSCacheTTL/AllowStaleJWKS.
// Introspection responses can be cached via IntrospectionCacheTTL.
type OAuth2Config struct {
	Mode OAuth2Mode

	Issuer      string
	Audience    string
	AllowedAlgs []string

	JWKSURL        string
	JWKSCacheTTL   time.Duration
	AllowStaleJWKS bool

	JWKS JWKSConfig

	Introspection         IntrospectionConfig
	IntrospectionCacheTTL time.Duration

	// Opaque controls opaque-token specific semantics.
	Opaque OpaquePolicy
}

// TokenTransportKind selects how the token is sent to the introspection endpoint.
type TokenTransportKind string

const (
	// TokenTransportBody sends the token in the POST body (default, RFC 7662).
	TokenTransportBody TokenTransportKind = "body"
	// TokenTransportHeader sends the token in a request header.
	TokenTransportHeader TokenTransportKind = "header"
)

// TokenTransport controls how the token is delivered to the introspection endpoint.
type TokenTransport struct {
	Kind   TokenTransportKind
	Field  string // body field name, default "token"
	Header string // header name when Kind == header, default "Authorization"
	Prefix string // header value prefix when Kind == header, e.g. "Bearer "
}

// ClientAuthKind selects how client credentials are sent.
type ClientAuthKind string

const (
	ClientAuthNone   ClientAuthKind = "none"
	ClientAuthBasic  ClientAuthKind = "basic"
	ClientAuthBody   ClientAuthKind = "body"
	ClientAuthHeader ClientAuthKind = "header"
	ClientAuthBearer ClientAuthKind = "bearer"
)

// ClientAuth configures client authentication for introspection or JWKS requests.
type ClientAuth struct {
	Kind         ClientAuthKind
	ClientID     string
	ClientSecret string
	HeaderName   string
	HeaderValue  string
}

// IntrospectionConfig holds RFC 7662 endpoint settings.
type IntrospectionConfig struct {
	Endpoint       string
	ClientID       string
	ClientSecret   string
	Timeout        time.Duration
	Auth           ClientAuth
	TokenTransport TokenTransport
	ExtraBody      map[string]string
	ExtraHeaders   map[string]string
}

// JWKSAuth configures authentication for JWKS endpoint requests.
type JWKSAuth struct {
	Kind        ClientAuthKind
	Username    string
	Password    string
	HeaderName  string
	HeaderValue string
	BearerToken string
}

// JWKSConfig holds JWKS endpoint settings with optional authentication.
type JWKSConfig struct {
	URL          string
	CacheTTL     time.Duration
	Auth         JWKSAuth
	ExtraHeaders map[string]string
}

// OpaquePolicy configures RFC 7662 opaque-token semantics.
//
// Defaults:
//   - RequireActive: true
//   - ExposeActiveClaim: false
//
// If RequireActive is true, responses with active != true are rejected.
// If ExposeActiveClaim is false, the "active" claim is removed before returning Result.
type OpaquePolicy struct {
	RequireActive     bool
	ExposeActiveClaim bool
}

// LuaClaimsPolicy configures an optional Lua script for advanced claim validation.
type LuaClaimsPolicy struct {
	Enabled bool
	Script  string
}

// Policies configures claim and actor validation.
type Policies struct {
	// Backward compatibility: TokenClaims applies to both types unless JWTClaims/OpaqueClaims override.
	TokenClaims ClaimPolicy
	// Type-specific claim policies. If empty and TokenClaims is non-empty, TokenClaims is used.
	JWTClaims    ClaimPolicy
	OpaqueClaims ClaimPolicy
	Actor        ActorPolicy
	Lua          LuaClaimsPolicy
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
	// Opaque defaults
	if !c.OAuth2.Opaque.RequireActive && !c.OAuth2.Opaque.ExposeActiveClaim {
		// Distinguish default zero-values from explicit false by setting RequireActive true when both are zero-values
		c.OAuth2.Opaque.RequireActive = true
	}
	// Policies defaults are zero-values (permit all), Actor disabled by default
	if c.Policies.Actor.ActorSubjectKey == "" {
		c.Policies.Actor.ActorSubjectKey = "sub"
	}
}

// Validate checks Config correctness and required fields per mode.
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
