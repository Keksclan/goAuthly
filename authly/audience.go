package authly

import (
	"fmt"
)

// audienceRuleIsZero reports whether the AudienceRule has no configuration set.
func audienceRuleIsZero(r AudienceRule) bool {
	return !r.AnyAudience && len(r.AnyOf) == 0 && len(r.AllOf) == 0 && len(r.Blocklist) == 0
}

// EffectiveAudienceRule returns the resolved AudienceRule for the given OAuth2Config.
// If AudienceRule is explicitly configured, it is returned as-is.
// Otherwise the legacy Audience string is converted:
//   - "*" => AnyAudience=true
//   - non-empty => AnyOf=[Audience]
//   - empty => zero AudienceRule (no enforcement)
func EffectiveAudienceRule(cfg OAuth2Config) AudienceRule {
	if !audienceRuleIsZero(cfg.AudienceRule) {
		return cfg.AudienceRule
	}
	if cfg.Audience == "*" {
		return AudienceRule{AnyAudience: true}
	}
	if cfg.Audience != "" {
		return AudienceRule{AnyOf: []string{cfg.Audience}}
	}
	return AudienceRule{}
}

// Validate checks the given token audiences against the AudienceRule.
//
// Matching logic order:
//  1. If Blocklist has any match => reject (always wins)
//  2. If AnyAudience=true => accept
//  3. If AllOf non-empty => require all present
//  4. If AnyOf non-empty => require at least one present
//  5. If both AllOf and AnyOf are empty => accept (no enforcement)
func (r AudienceRule) Validate(tokenAud []string) error {
	// Build a set for efficient lookup when lists are large.
	audSet := make(map[string]struct{}, len(tokenAud))
	for _, a := range tokenAud {
		audSet[a] = struct{}{}
	}

	// 1. Blocklist always wins.
	for _, blocked := range r.Blocklist {
		if _, ok := audSet[blocked]; ok {
			return fmt.Errorf("%w: %s", ErrAudienceBlocked, blocked)
		}
	}

	// 2. Wildcard: accept any audience (blocklist already checked).
	if r.AnyAudience {
		return nil
	}

	// 3. AllOf: every value must be present.
	if len(r.AllOf) > 0 {
		for _, required := range r.AllOf {
			if _, ok := audSet[required]; !ok {
				return fmt.Errorf("%w: required audience %q not found", ErrAudienceNotAllowed, required)
			}
		}
	}

	// 4. AnyOf: at least one value must be present.
	if len(r.AnyOf) > 0 {
		found := false
		for _, allowed := range r.AnyOf {
			if _, ok := audSet[allowed]; ok {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: none of %v matched", ErrAudienceNotAllowed, r.AnyOf)
		}
	}

	// 5. No rules configured => accept.
	return nil
}
