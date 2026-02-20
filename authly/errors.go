package authly

import (
	"errors"

	jwt "github.com/keksclan/goAuthly/internal/oauth/jwt"
)

// Package-level errors returned by the library.
var (
	// ErrUnsupportedMode indicates an unsupported authentication mode was selected.
	ErrUnsupportedMode = errors.New("unsupported auth mode")
	// ErrInvalidToken indicates the token format doesn't match the configured mode.
	ErrInvalidToken = errors.New("invalid token")
	// ErrClaimMissing is returned when a required claim is not present.
	ErrClaimMissing = errors.New("required claim missing")
	// ErrClaimForbidden is returned when a denied claim is present.
	ErrClaimForbidden = errors.New("claim is forbidden")
	// ErrClaimValueNotAllowed is returned when a claim value is not in the allow-list.
	ErrClaimValueNotAllowed = errors.New("claim value not allowed")
	// ErrUnknownClaimNotAllowed is returned when a claim is not in the allow-list.
	ErrUnknownClaimNotAllowed = errors.New("unknown claim not allowed")
	// ErrActorMissing is returned when the actor claim is required but missing.
	ErrActorMissing = errors.New("actor claim missing")
	// ErrActorNotAllowed is returned when the extracted actor subject is not allowed.
	ErrActorNotAllowed = errors.New("actor subject not allowed")
	// ErrLuaPolicy is returned when a Lua policy script rejects the token.
	ErrLuaPolicy = errors.New("lua policy violation")
	// ErrBasicAuthFailed is returned when Basic Auth credentials are invalid.
	ErrBasicAuthFailed = errors.New("basic auth failed")
	// ErrAudienceBlocked is returned when a token audience matches the blocklist.
	// Re-exported from the internal JWT validator so errors.Is works across packages.
	ErrAudienceBlocked = jwt.ErrAudienceBlocked
	// ErrAudienceMissing is returned when the token has no audience claim.
	ErrAudienceMissing = errors.New("audience missing")
	// ErrAudienceNotAllowed is returned when the token audience does not satisfy allow rules.
	// Re-exported from the internal JWT validator so errors.Is works across packages.
	ErrAudienceNotAllowed = jwt.ErrAudienceNotAllowed
	// ErrMissingRequiredMetadata is returned when a required metadata header is missing or empty.
	ErrMissingRequiredMetadata = errors.New("missing required metadata")
)
