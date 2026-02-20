package authly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	icache "github.com/keksclan/goAuthly/internal/cache"
	"github.com/keksclan/goAuthly/internal/jwk"
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
	Subject   string
	Actor     *ActorInfo
	Scopes    []string
	ExpiresAt time.Time
	Claims    map[string]any
	RawToken  string
}

// Engine verifies tokens according to the provided Config.
//
// Concurrency: Engine is safe for concurrent use if the provided Cache and HTTP client
// are safe for concurrent use (the defaults are). No method mutates shared state.
type Engine struct {
	cfg          Config
	httpc        *http.Client
	cache        Cache
	jwksMgr      *jwk.Manager
	jwtValidator *jwt.Validator
	introClient  *introspect.Client
	keepRawToken bool
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
	if e.httpc == nil {
		e.httpc = &http.Client{Timeout: 10 * time.Second}
	}
	if e.cache == nil {
		// default ristretto cache
		rc, err := icache.NewRistrettoCache(1<<15, 1<<20, 64)
		if err != nil {
			return nil, err
		}
		e.cache = rc
	}

	// JWKS manager
	m := jwk.NewManager(cacheAdapter{c: e.cache}, cfg.OAuth2.JWKSCacheTTL, cfg.OAuth2.AllowStaleJWKS)
	m.SetHTTPClient(e.httpc)
	e.jwksMgr = m

	// JWT validator with adapter over jwks manager
	prov := &managerProviderAdapter{mgr: m, url: cfg.OAuth2.JWKSURL}
	jv, err := jwt.New(jwt.Config{
		Issuer:      cfg.OAuth2.Issuer,
		Audience:    cfg.OAuth2.Audience,
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
	})
	if err != nil {
		return nil, fmt.Errorf("init introspection client: %w", err)
	}
	e.introClient = ic

	return e, nil
}

// Verify verifies the provided token according to the configured OAuth2 mode.
// It returns a populated Result on success.
func (e *Engine) Verify(ctx context.Context, token string) (*Result, error) {
	if e.cfg.Mode == AuthModeBasic {
		return nil, ErrUnsupportedMode
	}
	if e.cfg.Mode != AuthModeOAuth2 {
		return nil, ErrUnsupportedMode
	}

	looksJWT := strings.Count(token, ".") == 2
	switch e.cfg.OAuth2.Mode {
	case OAuth2JWTOnly:
		if !looksJWT {
			return nil, ErrInvalidToken
		}
		return e.verifyJWT(ctx, token)
	case OAuth2OpaqueOnly:
		if looksJWT {
			return nil, ErrInvalidToken
		}
		return e.verifyOpaque(ctx, token)
	case OAuth2JWTAndOpaque:
		if looksJWT {
			return e.verifyJWT(ctx, token)
		}
		return e.verifyOpaque(ctx, token)
	default:
		return nil, ErrUnsupportedMode
	}
}

func (e *Engine) verifyJWT(ctx context.Context, token string) (*Result, error) {
	claims, err := e.jwtValidator.Validate(ctx, token)
	if err != nil {
		return nil, err
	}
	// Policies
	if err := e.cfg.Policies.TokenClaims.Validate(claims.RawMap); err != nil {
		return nil, err
	}
	actor, err := e.cfg.Policies.Actor.ExtractAndValidate(claims.RawMap)
	if err != nil {
		return nil, err
	}
	res := &Result{
		Type:      TokenTypeJWT,
		Subject:   claims.Subject,
		Actor:     actor,
		Scopes:    claims.Scopes,
		ExpiresAt: claims.ExpiresAt,
		Claims:    claims.RawMap,
	}
	if e.keepRawToken {
		res.RawToken = token
	}
	return res, nil
}

func (e *Engine) verifyOpaque(ctx context.Context, token string) (*Result, error) {
	intro, err := e.cachedIntrospect(ctx, token)
	if err != nil {
		return nil, err
	}
	claims := e.introspectionToClaims(intro)

	if err := e.cfg.Policies.TokenClaims.Validate(claims); err != nil {
		return nil, err
	}
	actor, err := e.cfg.Policies.Actor.ExtractAndValidate(claims)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Type:      TokenTypeOpaque,
		Subject:   intro.Sub,
		Actor:     actor,
		Scopes:    strings.Fields(intro.Scope),
		ExpiresAt: time.Unix(intro.Exp, 0),
		Claims:    claims,
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
