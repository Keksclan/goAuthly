package authly

import "context"

// BasicAuthConfig configures Basic Authentication for the Engine.
//
// If Validator is set, it takes priority over the Users map.
// If only Users is provided, passwords are compared using bcrypt (constant-time).
// Passwords in the Users map must be bcrypt hashes — storing plaintext is a security violation.
//
// Security: bcrypt comparison is used to mitigate timing attacks.
// A dummy comparison is performed for unknown usernames to prevent user enumeration.
//
// Concurrency: BasicAuthConfig is immutable after passing to Config; do not mutate concurrently.
type BasicAuthConfig struct {
	// Enabled activates Basic Auth mode.
	Enabled bool

	// Users maps usernames to bcrypt-hashed passwords.
	// Use golang.org/x/crypto/bcrypt.GenerateFromPassword to produce hashes.
	Users map[string]string

	// Validator is an optional custom credential validation function.
	// When set, it takes priority over Users.
	// Must return (true, nil) for valid credentials, (false, nil) for invalid, or (false, err) on error.
	Validator func(ctx context.Context, username, password string) (bool, error)

	// Realm is returned in the WWW-Authenticate header. Defaults to "Restricted" if empty.
	Realm string
}

// TokenTypeBasic indicates a Basic Auth verification result.
const TokenTypeBasic TokenType = "basic"

// VerifyBasic verifies username and password using the configured Basic Auth settings.
//
// Returns a Result with Type "basic", Subject set to the username, and
// Claims containing "auth_method": "basic".
//
// If Basic Auth is not configured (Mode != AuthModeBasic or BasicAuth.Enabled is false),
// returns ErrUnsupportedMode.
//
// Concurrency: safe for concurrent use.
func (e *Engine) VerifyBasic(ctx context.Context, username, password string) (*Result, error) {
	if e.basicVerifier == nil {
		return nil, ErrUnsupportedMode
	}

	if err := e.basicVerifier.Verify(ctx, username, password); err != nil {
		return nil, err
	}

	claims := map[string]any{
		"auth_method": "basic",
		"sub":         username,
	}

	// Apply claim policies if configured (use TokenClaims as fallback).
	pol := e.cfg.Policies.TokenClaims
	if err := pol.Validate(claims); err != nil {
		return nil, err
	}

	// Apply Lua policy if enabled.
	if e.luaPolicy != nil {
		if err := e.luaPolicy.Evaluate(claims, "basic"); err != nil {
			return nil, err
		}
	}

	return &Result{
		Type:    TokenTypeBasic,
		Source:  "basic",
		Subject: username,
		Claims:  claims,
	}, nil
}
