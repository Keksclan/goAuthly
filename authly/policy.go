package authly

import (
	"errors"
	"fmt"
	"slices"
)

type ClaimPolicy struct {
	Allowlist      []string
	Denylist       []string
	EnforcedValues map[string][]any
	Required       []string
}

func (p ClaimPolicy) Validate(claims map[string]any) error {
	// Required claims must exist
	for _, k := range p.Required {
		if _, ok := claims[k]; !ok {
			return fmt.Errorf("%w: %s", ErrClaimMissing, k)
		}
	}
	// Denylist
	for _, k := range p.Denylist {
		if _, ok := claims[k]; ok {
			return fmt.Errorf("%w: %s", ErrClaimForbidden, k)
		}
	}
	// Allowlist check: reject unknown claims when allowlist non-empty
	if len(p.Allowlist) > 0 {
		for k := range claims {
			if !slices.Contains(p.Allowlist, k) {
				return fmt.Errorf("%w: %s", ErrUnknownClaimNotAllowed, k)
			}
		}
	}
	// Enforced values
	for k, allowed := range p.EnforcedValues {
		val, ok := claims[k]
		if !ok {
			continue // only enforce if present
		}
		if !valueAllowed(val, allowed) {
			return fmt.Errorf("%w: %s", ErrClaimValueNotAllowed, k)
		}
	}
	return nil
}

func valueAllowed(v any, allowed []any) bool {
	switch vv := v.(type) {
	case string:
		for _, a := range allowed {
			if as, ok := a.(string); ok && vv == as {
				return true
			}
		}
		return false
	case bool:
		for _, a := range allowed {
			if ab, ok := a.(bool); ok && vv == ab {
				return true
			}
		}
		return false
	case int, int32, int64, float32, float64:
		vf := toFloat64(vv)
		for _, a := range allowed {
			af, ok := a.(float64)
			if !ok {
				switch at := a.(type) {
				case int:
					af = float64(at)
				case int32:
					af = float64(at)
				case int64:
					af = float64(at)
				case float32:
					af = float64(at)
				default:
					continue
				}
			}
			if vf == af {
				return true
			}
		}
		return false
	case []any:
		// array of strings (any match allowed)
		for _, e := range vv {
			es, ok := e.(string)
			if !ok {
				continue
			}
			for _, a := range allowed {
				if as, ok := a.(string); ok && es == as {
					return true
				}
			}
		}
		return false
	case []string:
		for _, es := range vv {
			for _, a := range allowed {
				if as, ok := a.(string); ok && es == as {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

func toFloat64(v any) float64 {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int32:
		return float64(t)
	case int64:
		return float64(t)
	case float32:
		return float64(t)
	case float64:
		return t
	default:
		return 0
	}
}

type ActorPolicy struct {
	Enabled bool

	ActorClaimKey        string
	ActorSubjectKey      string
	AllowedActorSubjects []string
	ActorClaimsPolicy    *ClaimPolicy
}

type ActorInfo struct {
	Subject string
	Claims  map[string]any
}

func (ap ActorPolicy) ExtractAndValidate(claims map[string]any) (*ActorInfo, error) {
	if !ap.Enabled {
		return nil, nil
	}
	if ap.ActorClaimKey == "" {
		return nil, errors.New("actor claim key not configured")
	}
	raw, ok := claims[ap.ActorClaimKey]
	if !ok {
		return nil, ErrActorMissing
	}

	var subject string
	var actorClaims map[string]any
	switch t := raw.(type) {
	case string:
		subject = t
		actorClaims = map[string]any{"sub": subject}
	case map[string]any:
		key := ap.ActorSubjectKey
		if key == "" {
			key = "sub"
		}
		if s, ok := t[key].(string); ok {
			subject = s
			actorClaims = t
		} else {
			return nil, fmt.Errorf("%w: subject missing in actor object", ErrActorMissing)
		}
	default:
		return nil, fmt.Errorf("%w: unexpected actor claim type", ErrActorMissing)
	}

	if len(ap.AllowedActorSubjects) > 0 && !slices.Contains(ap.AllowedActorSubjects, subject) {
		return nil, ErrActorNotAllowed
	}

	if ap.ActorClaimsPolicy != nil {
		if err := ap.ActorClaimsPolicy.Validate(actorClaims); err != nil {
			return nil, err
		}
	}

	return &ActorInfo{Subject: subject, Claims: actorClaims}, nil
}
