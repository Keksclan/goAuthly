package authly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/keksclan/goAuthly/internal/basic"
	icache "github.com/keksclan/goAuthly/internal/cache"
	"github.com/keksclan/goAuthly/internal/jwk"
	"github.com/keksclan/goAuthly/internal/luaengine"
	"github.com/keksclan/goAuthly/internal/oauth/introspect"
	"github.com/keksclan/goAuthly/internal/oauth/jwt"
)

// TokenType describes the verified token kind.
type TokenType string

// Supported token types returned in Result.
const (
	// TokenTypeJWT indicates a JWT token was verified.
	TokenTypeJWT TokenType = "jwt"
	// TokenTypeOpaque indicates an opaque token was introspected and verified.
	TokenTypeOpaque TokenType = "opaque"
)

// Result contains verification output for a token.
//
// Concurrency: Result is immutable once returned.
type Result struct {
	Type      TokenType
	Source    string // "jwt" or "introspection"
	Subject   string
	Actor     *ActorInfo
	Scopes    []string
	ExpiresAt time.Time
	Claims    map[string]any
	RawToken  string
}

// IsJWT reports whether the result originated from a JWT verification.
func (r *Result) IsJWT() bool { return r != nil && r.Type == TokenTypeJWT }

// IsOpaque reports whether the result originated from an opaque token introspection.
func (r *Result) IsOpaque() bool { return r != nil && r.Type == TokenTypeOpaque }

// IsBasic reports whether the result originated from a Basic Auth verification.
func (r *Result) IsBasic() bool { return r != nil && r.Type == TokenTypeBasic }

// Engine verifies tokens according to the provided Config.
//
// Concurrency: Engine is safe for concurrent use if the provided Cache and HTTP client
// are safe for concurrent use (the defaults are). No method mutates shared state.
type Engine struct {
	cfg           Config
	httpc         *http.Client
	cache         Cache
	jwksMgr       *jwk.Manager
	jwtValidator  *jwt.Validator
	introClient   *introspect.Client
	basicVerifier *basic.Verifier
	luaPolicy     *luaengine.CompiledPolicy
	keepRawToken  bool
}

// cacheAdapter bridges public Cache to internal cache interface
type cacheAdapter struct{ c Cache }

func (a cacheAdapter) Get(key string) (any, bool) { return a.c.Get(key) }
func (a cacheAdapter) Set(key string, v any, cost int64, ttl time.Duration) bool {
	return a.c.Set(key, v, cost, ttl)
}
func (a cacheAdapter) Del(key string) { a.c.Del(key) }

// managerProviderAdapter adapts jwk.Manager to the jwt.Validator expected Provider
type managerProviderAdapter struct {
	mgr *jwk.Manager
	url string
}

func (a *managerProviderAdapter) GetKey(ctx context.Context, kid string) (any, error) {
	return a.mgr.GetKey(ctx, a.url, kid)
}
func (a *managerProviderAdapter) LoadFromURL(ctx context.Context, url string) error {
	a.url = url
	return nil
}

// New creates a new Engine using cfg and optional Options.
// Security: Ensure Issuer/Audience and algorithms are set to your expectations.
func New(cfg Config, opts ...Option) (*Engine, error) {
	cfg.setDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	e := &Engine{cfg: cfg}
	for _, opt := range opts {
		opt(e)
	}
	// Initialize Basic Auth verifier if configured
	if cfg.BasicAuth.Enabled {
		bv, err := basic.NewVerifier(basic.Config{
			Enabled:   true,
			Users:     cfg.BasicAuth.Users,
			Validator: cfg.BasicAuth.Validator,
			Realm:     cfg.BasicAuth.Realm,
		})
		if err != nil {
			return nil, fmt.Errorf("init basic auth: %w", err)
		}
		e.basicVerifier = bv
	}

	// Initialize OAuth2 components only when OAuth2 mode is active
	if cfg.Mode == AuthModeOAuth2 {
		if e.httpc == nil {
			e.httpc = &http.Client{Timeout: 10 * time.Second}
		}
		if e.cache == nil {
			rc, err := icache.NewRistrettoCache(1<<15, 1<<20, 64)
			if err != nil {
				return nil, err
			}
			e.cache = rc
		}

		// JWKS manager
		m := jwk.NewManager(cacheAdapter{c: e.cache}, cfg.OAuth2.JWKSCacheTTL, cfg.OAuth2.AllowStaleJWKS)
		m.SetHTTPClient(e.httpc)
		if cfg.OAuth2.JWKS.Auth.Kind != "" {
			m.SetAuth(jwk.AuthConfig{
				Kind:        jwk.AuthKind(cfg.OAuth2.JWKS.Auth.Kind),
				Username:    cfg.OAuth2.JWKS.Auth.Username,
				Password:    cfg.OAuth2.JWKS.Auth.Password,
				BearerToken: cfg.OAuth2.JWKS.Auth.BearerToken,
				HeaderName:  cfg.OAuth2.JWKS.Auth.HeaderName,
				HeaderValue: cfg.OAuth2.JWKS.Auth.HeaderValue,
			})
		}
		if len(cfg.OAuth2.JWKS.ExtraHeaders) > 0 {
			m.SetExtraHeaders(cfg.OAuth2.JWKS.ExtraHeaders)
		}
		e.jwksMgr = m

		// JWT validator
		prov := &managerProviderAdapter{mgr: m, url: cfg.OAuth2.JWKSURL}
		audRule := EffectiveAudienceRule(cfg.OAuth2)
		jv, err := jwt.New(jwt.Config{
			Issuer:   cfg.OAuth2.Issuer,
			Audience: cfg.OAuth2.Audience,
			AudienceRule: jwt.AudienceRule{
				AnyAudience: audRule.AnyAudience,
				AnyOf:       audRule.AnyOf,
				AllOf:       audRule.AllOf,
				Blocklist:   audRule.Blocklist,
			},
			AllowedAlgs: cfg.OAuth2.AllowedAlgs,
		}, prov)
		if err != nil {
			return nil, fmt.Errorf("init jwt validator: %w", err)
		}
		e.jwtValidator = jv

		// Introspection client
		ic, err := introspect.New(introspect.Config{
			Endpoint:     cfg.OAuth2.Introspection.Endpoint,
			ClientID:     cfg.OAuth2.Introspection.ClientID,
			ClientSecret: cfg.OAuth2.Introspection.ClientSecret,
			Timeout:      cfg.OAuth2.Introspection.Timeout,
			Auth: introspect.ClientAuth{
				Kind:         introspect.ClientAuthKind(cfg.OAuth2.Introspection.Auth.Kind),
				ClientID:     cfg.OAuth2.Introspection.Auth.ClientID,
				ClientSecret: cfg.OAuth2.Introspection.Auth.ClientSecret,
				HeaderName:   cfg.OAuth2.Introspection.Auth.HeaderName,
				HeaderValue:  cfg.OAuth2.Introspection.Auth.HeaderValue,
			},
			TokenTransport: introspect.TokenTransport{
				Kind:   introspect.TokenTransportKind(cfg.OAuth2.Introspection.TokenTransport.Kind),
				Field:  cfg.OAuth2.Introspection.TokenTransport.Field,
				Header: cfg.OAuth2.Introspection.TokenTransport.Header,
				Prefix: cfg.OAuth2.Introspection.TokenTransport.Prefix,
			},
			ExtraBody:    cfg.OAuth2.Introspection.ExtraBody,
			ExtraHeaders: cfg.OAuth2.Introspection.ExtraHeaders,
		})
		if err != nil {
			return nil, fmt.Errorf("init introspection client: %w", err)
		}
		e.introClient = ic
	}

	// Compile Lua policy if enabled
	if cfg.Policies.Lua.Enabled && cfg.Policies.Lua.Script != "" {
		cp, err := luaengine.Compile(cfg.Policies.Lua.Script)
		if err != nil {
			return nil, fmt.Errorf("compile lua policy: %w", err)
		}
		e.luaPolicy = cp
	}

	return e, nil
}

// Verify verifies the provided token according to the configured OAuth2 mode.
// It returns a populated Result on success.
// tokenVerifier defines a common interface for specific token verifiers.
type tokenVerifier interface {
	Verify(ctx context.Context, token string) (*verificationResult, error)
}

type verificationResult struct {
	tokenType TokenType
	source    string
	subject   string
	scopes    []string
	expiresAt time.Time
	claims    map[string]any
}

// jwtVerifier verifies JWT tokens.
type jwtVerifier struct{ e *Engine }

func (v *jwtVerifier) Verify(ctx context.Context, token string) (*verificationResult, error) {
	claims, err := v.e.jwtValidator.Validate(ctx, token)
	if err != nil {
		return nil, err
	}
	return &verificationResult{
		tokenType: TokenTypeJWT,
		source:    "jwt",
		subject:   claims.Subject,
		scopes:    claims.Scopes,
		expiresAt: claims.ExpiresAt,
		claims:    claims.RawMap,
	}, nil
}

// opaqueVerifier verifies opaque tokens via introspection.
type opaqueVerifier struct{ e *Engine }

func (v *opaqueVerifier) Verify(ctx context.Context, token string) (*verificationResult, error) {
	ir, err := v.e.cachedIntrospect(ctx, token)
	if v.e.cfg.OAuth2.Opaque.RequireActive {
		// When active is required, any inactive error leads to rejection.
		if err != nil {
			return nil, err
		}
		if ir == nil || !ir.Active {
			return nil, introspect.ErrTokenInactive
		}
	} else {
		// When not required, allow proceeding even if inactive error was returned.
		// ir may be non-nil alongside ErrTokenInactive from client.
		if ir == nil {
			return nil, fmt.Errorf("introspection response missing")
		}
	}
	claims := v.e.introspectionToClaims(ir)
	return &verificationResult{
		tokenType: TokenTypeOpaque,
		source:    "introspection",
		subject:   ir.Sub,
		scopes:    strings.Fields(ir.Scope),
		expiresAt: time.Unix(ir.Exp, 0),
		claims:    claims,
	}, nil
}

func (e *Engine) Verify(ctx context.Context, token string) (*Result, error) {
	if e.cfg.Mode == AuthModeBasic {
		return nil, ErrUnsupportedMode
	}
	if e.cfg.Mode != AuthModeOAuth2 {
		return nil, ErrUnsupportedMode
	}
	if token == "" {
		return nil, ErrInvalidToken
	}

	looksJWT := strings.Count(token, ".") == 2
	var v tokenVerifier
	switch e.cfg.OAuth2.Mode {
	case OAuth2JWTOnly:
		if !looksJWT {
			return nil, ErrInvalidToken
		}
		v = &jwtVerifier{e: e}
	case OAuth2OpaqueOnly:
		if looksJWT {
			return nil, ErrInvalidToken
		}
		v = &opaqueVerifier{e: e}
	case OAuth2JWTAndOpaque:
		if looksJWT {
			v = &jwtVerifier{e: e}
		} else {
			v = &opaqueVerifier{e: e}
		}
	default:
		return nil, ErrUnsupportedMode
	}

	vr, err := v.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	// Apply claim policies (type-aware with backward compatibility).
	pol := e.selectClaimPolicy(vr.tokenType)
	if len(pol.ApplyTo) == 0 || slices.Contains(pol.ApplyTo, vr.tokenType) {
		if err := pol.Validate(vr.claims); err != nil {
			return nil, err
		}
	}

	// Apply Lua policy (if enabled, runs after declarative claim policy)
	if e.luaPolicy != nil {
		if err := e.luaPolicy.Evaluate(vr.claims, string(vr.tokenType)); err != nil {
			return nil, err
		}
	}

	actor, err := e.cfg.Policies.Actor.ExtractAndValidate(vr.claims)
	if err != nil {
		return nil, err
	}

	// Opaque-specific post-processing: hide "active" unless configured to expose.
	if vr.tokenType == TokenTypeOpaque && !e.cfg.OAuth2.Opaque.ExposeActiveClaim {
		delete(vr.claims, "active")
	}

	res := &Result{
		Type:      vr.tokenType,
		Source:    vr.source,
		Subject:   vr.subject,
		Actor:     actor,
		Scopes:    vr.scopes,
		ExpiresAt: vr.expiresAt,
		Claims:    vr.claims,
	}
	if e.keepRawToken {
		res.RawToken = token
	}
	return res, nil
}

func (e *Engine) cachedIntrospect(ctx context.Context, token string) (*introspect.IntrospectionResponse, error) {
	key := e.introspectionCacheKey(token)
	if v, ok := e.cache.Get(key); ok {
		if ir, ok := v.(*introspect.IntrospectionResponse); ok {
			return ir, nil
		}
	}
	ir, err := e.introClient.Introspect(ctx, token)
	if err != nil {
		// If the token is inactive, the client returns both a response and ErrTokenInactive.
		// We propagate both to let the verifier apply OpaquePolicy semantics.
		if errors.Is(err, introspect.ErrTokenInactive) {
			return ir, err
		}
		return nil, err
	}
	// Cache only active tokens
	if ir.Active {
		e.cache.Set(key, ir, 1, e.cfg.OAuth2.IntrospectionCacheTTL)
		// ensure visibility for subsequent immediate reads (ristretto is async)
		if w, ok := any(e.cache).(interface{ Wait() }); ok {
			w.Wait()
		}
	}
	return ir, nil
}

func (e *Engine) introspectionCacheKey(token string) string {
	s := sha256.Sum256([]byte(token))
	return "introspect:" + hex.EncodeToString(s[:]) + ":" + e.cfg.OAuth2.Introspection.Endpoint
}

func (e *Engine) introspectionToClaims(ir *introspect.IntrospectionResponse) map[string]any {
	m := map[string]any{}
	m["active"] = ir.Active
	if ir.Scope != "" {
		m["scope"] = ir.Scope
	}
	if ir.ClientID != "" {
		m["client_id"] = ir.ClientID
	}
	if ir.Username != "" {
		m["username"] = ir.Username
	}
	if ir.TokenType != "" {
		m["token_type"] = ir.TokenType
	}
	if ir.Exp != 0 {
		m["exp"] = ir.Exp
	}
	if ir.Iat != 0 {
		m["iat"] = ir.Iat
	}
	if ir.Nbf != 0 {
		m["nbf"] = ir.Nbf
	}
	if ir.Sub != "" {
		m["sub"] = ir.Sub
	}
	if ir.Aud != nil {
		m["aud"] = ir.Aud
	}
	if ir.Iss != "" {
		m["iss"] = ir.Iss
	}
	if ir.Jti != "" {
		m["jti"] = ir.Jti
	}
	for k, v := range ir.Extras {
		m[k] = v
	}
	return m
}

// selectClaimPolicy returns the effective claim policy for the given token type,
// honoring backward compatibility with the legacy TokenClaims field.
func (e *Engine) selectClaimPolicy(tt TokenType) ClaimPolicy {
	switch tt {
	case TokenTypeJWT:
		if claimPolicyIsZero(e.cfg.Policies.JWTClaims) && !claimPolicyIsZero(e.cfg.Policies.TokenClaims) {
			return e.cfg.Policies.TokenClaims
		}
		return e.cfg.Policies.JWTClaims
	case TokenTypeOpaque:
		if claimPolicyIsZero(e.cfg.Policies.OpaqueClaims) && !claimPolicyIsZero(e.cfg.Policies.TokenClaims) {
			return e.cfg.Policies.TokenClaims
		}
		return e.cfg.Policies.OpaqueClaims
	default:
		return e.cfg.Policies.TokenClaims
	}
}

func claimPolicyIsZero(p ClaimPolicy) bool {
	return len(p.Allowlist) == 0 && len(p.Denylist) == 0 && len(p.Required) == 0 && len(p.ApplyTo) == 0 && (p.EnforcedValues == nil || len(p.EnforcedValues) == 0)
}
