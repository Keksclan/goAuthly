package authly

import "errors"

var (
	ErrUnsupportedMode        = errors.New("unsupported auth mode")
	ErrInvalidToken           = errors.New("invalid token")
	ErrClaimMissing           = errors.New("required claim missing")
	ErrClaimForbidden         = errors.New("claim is forbidden")
	ErrClaimValueNotAllowed   = errors.New("claim value not allowed")
	ErrUnknownClaimNotAllowed = errors.New("unknown claim not allowed")
	ErrActorMissing           = errors.New("actor claim missing")
	ErrActorNotAllowed        = errors.New("actor subject not allowed")
)
