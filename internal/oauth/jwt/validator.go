package jwt

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/internal/jwk"
)

// defaultClockSkew is used when ClockSkew is zero.
const defaultClockSkew = 30 * time.Second

// AudienceRule mirrors authly.AudienceRule for internal use.
type AudienceRule struct {
	AnyAudience bool
	AnyOf       []string
	AllOf       []string
	Blocklist   []string
}

// ValidatorMode selects the validation strategy.
type ValidatorMode string

const (
	// ValidatorModeStandard is the default mode with no special optimizations.
	ValidatorModeStandard ValidatorMode = "standard"
	// ValidatorModeThroughput enables high-throughput optimizations such as
	// object pooling and precomputed structures for reduced allocations.
	ValidatorModeThroughput ValidatorMode = "throughput"
)

// MetricsCollector receives validation outcome counters.
// All methods must be safe for concurrent use.
// Implementations must never log or store tokens or claims.
type MetricsCollector interface {
	ValidationOK()
	ValidationFailed(reason string)
}

// Failure reason constants used with MetricsCollector.
const (
	FailReasonAlg       = "alg"
	FailReasonKid       = "kid"
	FailReasonIssuer    = "iss"
	FailReasonAudience  = "aud"
	FailReasonExpired   = "exp"
	FailReasonNbf       = "nbf"
	FailReasonIat       = "iat"
	FailReasonSignature = "signature"
	FailReasonParse     = "parse"
)

type Config struct {
	Issuer       string
	Audience     string
	AudienceRule AudienceRule
	AllowedAlgs  []string
	ClockSkew    time.Duration
	// JWKSEnabled indicates that JWKS key resolution is active,
	// which makes the kid header mandatory.
	JWKSEnabled bool
	// Mode selects standard or throughput validation. Default is standard.
	Mode ValidatorMode
	// Metrics receives optional validation counters. No-op when nil.
	Metrics MetricsCollector
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

// Validator verifies JWT tokens. It is safe for concurrent use.
type Validator struct {
	cfg           Config
	keys          jwk.Provider
	allowedAlgSet map[string]struct{}
	clockSkew     time.Duration
	// parserOpts is precomputed once at construction and reused for every
	// Validate call, avoiding repeated slice allocation.
	parserOpts []jwt.ParserOption
	// Precomputed audience lookup sets (immutable after build).
	audAnyOfSet     map[string]struct{}
	audAllOfSet     map[string]struct{}
	audBlockSet     map[string]struct{}
	audRuleResolved bool
	audRule         AudienceRule
	// throughput mode: pool for Claims objects
	claimsPool *sync.Pool
	metrics    MetricsCollector
	// highThroughput caches the mode check result
	highThroughput bool
}

// validationResult is pooled in throughput mode to reduce allocations.
type validationResult struct {
	claims Claims
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
	v.clockSkew = cfg.ClockSkew
	if v.clockSkew == 0 {
		v.clockSkew = defaultClockSkew
	}

	// Precompute parser options once.
	v.parserOpts = []jwt.ParserOption{
		jwt.WithLeeway(v.clockSkew),
		jwt.WithExpirationRequired(),
	}
	if len(cfg.AllowedAlgs) > 0 {
		v.parserOpts = append(v.parserOpts, jwt.WithValidMethods(cfg.AllowedAlgs))
	}

	// Precompute the effective audience rule and lookup sets.
	v.resolveAudienceRule()

	// Throughput mode setup.
	v.metrics = cfg.Metrics
	if cfg.Mode == ValidatorModeThroughput {
		v.highThroughput = true
		v.claimsPool = &sync.Pool{
			New: func() any { return &validationResult{} },
		}
	}

	return v, nil
}

// resolveAudienceRule precomputes the effective audience rule and builds
// O(1) lookup sets for AnyOf, AllOf and Blocklist.
func (v *Validator) resolveAudienceRule() {
	rule := v.cfg.AudienceRule
	if audienceRuleIsZero(rule) {
		if v.cfg.Audience == "*" {
			rule = AudienceRule{AnyAudience: true}
		} else if v.cfg.Audience != "" {
			rule = AudienceRule{AnyOf: []string{v.cfg.Audience}}
		}
	}
	v.audRule = rule
	v.audRuleResolved = true

	if len(rule.AnyOf) > 0 {
		v.audAnyOfSet = make(map[string]struct{}, len(rule.AnyOf))
		for _, a := range rule.AnyOf {
			v.audAnyOfSet[a] = struct{}{}
		}
	}
	if len(rule.AllOf) > 0 {
		v.audAllOfSet = make(map[string]struct{}, len(rule.AllOf))
		for _, a := range rule.AllOf {
			v.audAllOfSet[a] = struct{}{}
		}
	}
	if len(rule.Blocklist) > 0 {
		v.audBlockSet = make(map[string]struct{}, len(rule.Blocklist))
		for _, a := range rule.Blocklist {
			v.audBlockSet[a] = struct{}{}
		}
	}
}

func (v *Validator) Validate(ctx context.Context, tokenStr string) (*Claims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		// Algorithm check inside keyfunc as a defense-in-depth measure.
		if v.allowedAlgSet != nil {
			if _, ok := v.allowedAlgSet[t.Method.Alg()]; !ok {
				v.emitFailure(FailReasonAlg)
				return nil, fmt.Errorf("algorithm not allowed")
			}
		}

		kid, _ := t.Header["kid"].(string)

		// When JWKS is enabled, kid is mandatory.
		if v.cfg.JWKSEnabled && kid == "" {
			v.emitFailure(FailReasonKid)
			return nil, fmt.Errorf("token missing required kid header")
		}

		if kid == "" {
			v.emitFailure(FailReasonKid)
			return nil, fmt.Errorf("missing kid in header")
		}

		return v.keys.GetKey(ctx, kid)
	}, v.parserOpts...)

	if err != nil {
		// Classify the failure for metrics when not already emitted.
		v.classifyParseError(err)
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		v.emitFailure(FailReasonParse)
		return nil, fmt.Errorf("invalid claims type")
	}

	res := v.acquireClaims()
	res.RawMap = mapClaims

	if sub, err := mapClaims.GetSubject(); err == nil {
		res.Subject = sub
	}
	if iss, err := mapClaims.GetIssuer(); err == nil {
		res.Issuer = iss
	}
	if aud, err := mapClaims.GetAudience(); err == nil {
		res.Audience = aud
	}
	if exp, err := mapClaims.GetExpirationTime(); err == nil && exp != nil {
		res.ExpiresAt = exp.Time
	}
	if iat, err := mapClaims.GetIssuedAt(); err == nil && iat != nil {
		res.IssuedAt = iat.Time
	}
	if nbf, err := mapClaims.GetNotBefore(); err == nil && nbf != nil {
		res.NotBefore = nbf.Time
	}

	if scope, ok := mapClaims["scope"].(string); ok {
		res.Scopes = strings.Fields(scope)
	}

	// Capture time once for all post-parse checks.
	now := time.Now()

	// Strict issuer validation.
	if v.cfg.Issuer != "" && res.Issuer != v.cfg.Issuer {
		v.emitFailure(FailReasonIssuer)
		return nil, fmt.Errorf("token issuer mismatch")
	}

	// Validate iat (issued-at) is not in the future beyond clock skew.
	if !res.IssuedAt.IsZero() {
		if res.IssuedAt.After(now.Add(v.clockSkew)) {
			v.emitFailure(FailReasonIat)
			return nil, fmt.Errorf("token issued in the future")
		}
	}

	// Audience validation via precomputed rule.
	if err := v.validateAudience(res.Audience); err != nil {
		v.emitFailure(FailReasonAudience)
		return nil, err
	}

	v.emitOK()
	return res, nil
}

// acquireClaims returns a Claims pointer, using the pool in throughput mode.
func (v *Validator) acquireClaims() *Claims {
	if v.highThroughput {
		vr := v.claimsPool.Get().(*validationResult)
		// Reset all fields to avoid leaking data from previous validations.
		vr.claims = Claims{}
		return &vr.claims
	}
	return &Claims{}
}

// emitOK reports a successful validation if a metrics collector is set.
func (v *Validator) emitOK() {
	if v.metrics != nil {
		v.metrics.ValidationOK()
	}
}

// emitFailure reports a failed validation with reason if a metrics collector is set.
func (v *Validator) emitFailure(reason string) {
	if v.metrics != nil {
		v.metrics.ValidationFailed(reason)
	}
}

// classifyParseError emits a failure reason based on the parse/validation error.
func (v *Validator) classifyParseError(err error) {
	if v.metrics == nil {
		return
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "expired"):
		v.metrics.ValidationFailed(FailReasonExpired)
	case strings.Contains(msg, "not valid yet"):
		v.metrics.ValidationFailed(FailReasonNbf)
	case strings.Contains(msg, "signing method"):
		v.metrics.ValidationFailed(FailReasonAlg)
	case strings.Contains(msg, "signature"):
		v.metrics.ValidationFailed(FailReasonSignature)
	default:
		v.metrics.ValidationFailed(FailReasonParse)
	}
}

// audienceRuleIsZero reports whether the AudienceRule has no configuration.
func audienceRuleIsZero(r AudienceRule) bool {
	return !r.AnyAudience && len(r.AnyOf) == 0 && len(r.AllOf) == 0 && len(r.Blocklist) == 0
}

// validateAudience checks the token audiences against the precomputed rule.
// The effective rule and lookup sets are resolved once at construction time.
func (v *Validator) validateAudience(tokenAud []string) error {
	rule := v.audRule

	// No audience enforcement configured.
	if !rule.AnyAudience && len(rule.AnyOf) == 0 && len(rule.AllOf) == 0 && len(rule.Blocklist) == 0 {
		return nil
	}

	// 1. Blocklist always wins — use precomputed set for O(1) lookup.
	if len(v.audBlockSet) > 0 {
		for _, a := range tokenAud {
			if _, ok := v.audBlockSet[a]; ok {
				return fmt.Errorf("audience blocked: %s", a)
			}
		}
	}

	// 2. Wildcard.
	if rule.AnyAudience {
		return nil
	}

	// Build token audience set only when needed for AllOf/AnyOf.
	var audSet map[string]struct{}
	lazyAudSet := func() map[string]struct{} {
		if audSet == nil {
			audSet = make(map[string]struct{}, len(tokenAud))
			for _, a := range tokenAud {
				audSet[a] = struct{}{}
			}
		}
		return audSet
	}

	// 3. AllOf: every value must be present.
	if len(rule.AllOf) > 0 {
		s := lazyAudSet()
		for _, required := range rule.AllOf {
			if _, ok := s[required]; !ok {
				return fmt.Errorf("audience not allowed: required audience %q not found", required)
			}
		}
	}

	// 4. AnyOf: at least one must be present.
	if len(rule.AnyOf) > 0 {
		found := false
		// When token has few audiences, check each against precomputed set.
		if len(tokenAud) <= len(rule.AnyOf) {
			for _, a := range tokenAud {
				if _, ok := v.audAnyOfSet[a]; ok {
					found = true
					break
				}
			}
		} else {
			s := lazyAudSet()
			for _, allowed := range rule.AnyOf {
				if _, ok := s[allowed]; ok {
					found = true
					break
				}
			}
		}
		if !found {
			return fmt.Errorf("audience not allowed: none of %v matched", rule.AnyOf)
		}
	}

	return nil
}

// ---- JWKS key index for O(1) lookup ----

// KeyIndex provides O(1) kid-based key lookup. It is built atomically
// on each JWKS refresh and swapped via atomic.Pointer.
type KeyIndex struct {
	keys map[string]any // kid -> raw public key
}

// IndexedKeyProvider wraps a jwk.Provider and maintains an atomic key index
// for O(1) kid lookup, falling back to the underlying provider on miss.
type IndexedKeyProvider struct {
	inner jwk.Provider
	index atomic.Pointer[KeyIndex]
}

// NewIndexedKeyProvider creates an IndexedKeyProvider wrapping the given provider.
func NewIndexedKeyProvider(inner jwk.Provider) *IndexedKeyProvider {
	p := &IndexedKeyProvider{inner: inner}
	p.index.Store(&KeyIndex{keys: make(map[string]any)})
	return p
}

// RebuildIndex replaces the key index atomically with the provided kid->key map.
func (p *IndexedKeyProvider) RebuildIndex(keys map[string]any) {
	p.index.Store(&KeyIndex{keys: keys})
}

// GetKey performs O(1) lookup by kid, falling back to the underlying provider.
func (p *IndexedKeyProvider) GetKey(ctx context.Context, kid string) (any, error) {
	idx := p.index.Load()
	if key, ok := idx.keys[kid]; ok {
		return key, nil
	}
	// Fallback to underlying provider (e.g. after rotation before index rebuild).
	return p.inner.GetKey(ctx, kid)
}

// LoadFromURL delegates to the underlying provider.
func (p *IndexedKeyProvider) LoadFromURL(ctx context.Context, url string) error {
	return p.inner.LoadFromURL(ctx, url)
}
