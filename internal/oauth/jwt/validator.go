package jwt

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keksclan/goAuthly/internal/jwk"
)

// Sentinel errors for audience validation failures.
var (
	ErrAudienceBlocked    = errors.New("audience blocked")
	ErrAudienceNotAllowed = errors.New("audience not allowed")
)

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
	// precomputed structures for reduced allocations.
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
	audAnyOfSet map[string]struct{}
	audAllOfSet map[string]struct{}
	audBlockSet map[string]struct{}
	audRule     AudienceRule
	metrics     MetricsCollector
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

	// Precompute the effective audience rule (always needed).
	v.resolveAudienceRule()

	// In throughput mode, precompute parser options and audience lookup sets
	// once at construction time to avoid repeated allocations.
	if cfg.Mode == ValidatorModeThroughput {
		v.parserOpts = v.buildParserOpts()
		v.buildAudienceSets()
	}

	v.metrics = cfg.Metrics

	return v, nil
}

// resolveAudienceRule normalises the effective audience rule from config.
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
}

// buildParserOpts returns the jwt.ParserOption slice for this validator.
func (v *Validator) buildParserOpts() []jwt.ParserOption {
	opts := []jwt.ParserOption{
		jwt.WithLeeway(v.clockSkew),
		jwt.WithExpirationRequired(),
	}
	if len(v.cfg.AllowedAlgs) > 0 {
		opts = append(opts, jwt.WithValidMethods(v.cfg.AllowedAlgs))
	}
	return opts
}

// buildAudienceSets creates O(1) lookup sets for AnyOf, AllOf and Blocklist.
// Called only in throughput mode.
func (v *Validator) buildAudienceSets() {
	rule := v.audRule
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
	keyfuncEmitted := false
	// Use precomputed parser options in throughput mode; build inline otherwise.
	parserOpts := v.parserOpts
	if parserOpts == nil {
		parserOpts = v.buildParserOpts()
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		// Algorithm check inside keyfunc as a defense-in-depth measure.
		if v.allowedAlgSet != nil {
			if _, ok := v.allowedAlgSet[t.Method.Alg()]; !ok {
				v.emitFailure(FailReasonAlg)
				keyfuncEmitted = true
				return nil, fmt.Errorf("algorithm not allowed")
			}
		}

		kid, _ := t.Header["kid"].(string)

		// When JWKS is enabled, kid is mandatory.
		if v.cfg.JWKSEnabled && kid == "" {
			v.emitFailure(FailReasonKid)
			keyfuncEmitted = true
			return nil, fmt.Errorf("token missing required kid header")
		}

		return v.keys.GetKey(ctx, kid)
	}, parserOpts...)

	if err != nil {
		// Classify the failure for metrics only when not already emitted by the keyfunc.
		if !keyfuncEmitted {
			v.classifyParseError(err)
		}
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

// acquireClaims returns a freshly allocated Claims pointer.
func (v *Validator) acquireClaims() *Claims {
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

// validateAudience checks the token audiences against the configured rule.
// In throughput mode, precomputed O(1) lookup sets are used; in standard mode,
// linear scans are performed.
func (v *Validator) validateAudience(tokenAud []string) error {
	rule := v.audRule

	// No audience enforcement configured.
	if !rule.AnyAudience && len(rule.AnyOf) == 0 && len(rule.AllOf) == 0 && len(rule.Blocklist) == 0 {
		return nil
	}

	// 1. Blocklist always wins.
	if len(rule.Blocklist) > 0 {
		if v.audBlockSet != nil {
			// Throughput mode: O(1) lookup via precomputed set.
			for _, a := range tokenAud {
				if _, ok := v.audBlockSet[a]; ok {
					return ErrAudienceBlocked
				}
			}
		} else {
			// Standard mode: linear scan.
			for _, a := range tokenAud {
				for _, blocked := range rule.Blocklist {
					if a == blocked {
						return ErrAudienceBlocked
					}
				}
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
				return ErrAudienceNotAllowed
			}
		}
	}

	// 4. AnyOf: at least one must be present.
	if len(rule.AnyOf) > 0 {
		found := false
		if v.audAnyOfSet != nil {
			// Throughput mode: use precomputed set for O(1) lookup.
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
		} else {
			// Standard mode: linear scan.
			for _, a := range tokenAud {
				for _, allowed := range rule.AnyOf {
					if a == allowed {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}
		if !found {
			return ErrAudienceNotAllowed
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

// RebuildIndex replaces the key index atomically with a defensive copy of the
// provided kid->key map, preventing aliasing with the caller's map.
func (p *IndexedKeyProvider) RebuildIndex(keys map[string]any) {
	cp := maps.Clone(keys)
	p.index.Store(&KeyIndex{keys: cp})
}

// GetKey performs O(1) lookup by kid. When the kid exists in the index it
// still consults the underlying provider so that same-kid key rotations
// (where the key material changed but the kid stayed the same) are detected.
// If the inner provider returns a different key, the fresher key wins.
func (p *IndexedKeyProvider) GetKey(ctx context.Context, kid string) (any, error) {
	idx := p.index.Load()
	indexKey, inIndex := idx.keys[kid]

	// Always ask the inner provider for the freshest key.
	innerKey, innerErr := p.inner.GetKey(ctx, kid)
	if innerErr == nil {
		return innerKey, nil
	}

	// Inner failed but index had the kid – return the cached copy.
	if inIndex {
		return indexKey, nil
	}

	return nil, innerErr
}

// LoadFromURL delegates to the underlying provider and rebuilds the index
// atomically from the provider's current key set.
func (p *IndexedKeyProvider) LoadFromURL(ctx context.Context, url string) error {
	if err := p.inner.LoadFromURL(ctx, url); err != nil {
		return err
	}
	if keys := p.inner.Keys(); keys != nil {
		p.RebuildIndex(keys)
	}
	return nil
}

// Keys returns a snapshot of the current index keys.
func (p *IndexedKeyProvider) Keys() map[string]any {
	idx := p.index.Load()
	return maps.Clone(idx.keys)
}
