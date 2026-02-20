// Package basic provides Basic Authentication verification using bcrypt hashed passwords
// or a custom validator function.
//
// Concurrency: All exported functions and types are safe for concurrent use.
// The Verifier does not mutate any shared state after construction.
package basic

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Predefined errors for Basic Auth verification.
var (
	// ErrInvalidCredentials is returned when the username/password combination is incorrect.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrBasicAuthDisabled is returned when Basic Auth verification is attempted but not enabled.
	ErrBasicAuthDisabled = errors.New("basic auth is not enabled")
	// ErrNoCredentialSource is returned when neither Users map nor Validator is configured.
	ErrNoCredentialSource = errors.New("no credential source configured")
)

// Config configures the Basic Auth verifier.
//
// If Validator is set, it takes priority over the Users map.
// If only Users is set, passwords are compared using bcrypt.
// Realm is used for the WWW-Authenticate header value; defaults to "Restricted" if empty.
type Config struct {
	// Enabled controls whether Basic Auth verification is active.
	Enabled bool

	// Users maps usernames to bcrypt-hashed passwords.
	// Passwords must be bcrypt hashes (e.g., output of bcrypt.GenerateFromPassword).
	// Storing plaintext passwords here is a security violation.
	Users map[string]string

	// Validator is an optional custom validation function.
	// When set, it takes priority over the Users map.
	// The function must return (true, nil) for valid credentials,
	// (false, nil) for invalid credentials, or (false, err) on internal error.
	Validator func(ctx context.Context, username, password string) (bool, error)

	// Realm is the authentication realm returned in WWW-Authenticate headers.
	// If empty, defaults to "Restricted".
	Realm string
}

// Verifier performs Basic Auth credential verification.
//
// Concurrency: Verifier is safe for concurrent use. It does not mutate state after construction.
// Zero-value is not usable; create via NewVerifier.
type Verifier struct {
	cfg Config
	// dummyHash is a valid bcrypt hash whose cost matches the maximum cost
	// found among configured user hashes. It is used when a looked-up user
	// does not exist so that bcrypt.CompareHashAndPassword always runs at a
	// realistic cost, preventing timing-based user enumeration attacks.
	dummyHash []byte
}

// NewVerifier creates a new Basic Auth verifier from the provided Config.
//
// Returns ErrBasicAuthDisabled if cfg.Enabled is false.
// Returns ErrNoCredentialSource if neither Users nor Validator is configured.
func NewVerifier(cfg Config) (*Verifier, error) {
	if !cfg.Enabled {
		return nil, ErrBasicAuthDisabled
	}
	if cfg.Validator == nil && len(cfg.Users) == 0 {
		return nil, ErrNoCredentialSource
	}
	if cfg.Realm == "" {
		cfg.Realm = "Restricted"
	}

	v := &Verifier{cfg: cfg}

	// Compute a per-verifier dummy hash whose bcrypt cost matches the maximum
	// cost among configured user hashes. This ensures that the non-existent-user
	// path takes the same time as a real password check, preventing timing-based
	// user enumeration even when the configured cost differs from the default.
	if len(cfg.Users) > 0 {
		maxCost := 10 // sensible fallback
		for _, hashed := range cfg.Users {
			c, err := bcrypt.Cost([]byte(hashed))
			if err != nil {
				continue // fall back to current maxCost on invalid hashes
			}
			maxCost = max(maxCost, c)
		}
		dh, err := bcrypt.GenerateFromPassword([]byte("dummy-password"), maxCost)
		if err != nil {
			return nil, fmt.Errorf("basic auth: generate dummy hash: %w", err)
		}
		v.dummyHash = dh
	}

	return v, nil
}

// Verify checks the provided username and password.
//
// If a custom Validator is configured, it is used exclusively.
// Otherwise, the Users map is consulted with bcrypt comparison.
//
// Returns nil on success, or an error describing the failure.
// On invalid credentials, the returned error wraps ErrInvalidCredentials.
func (v *Verifier) Verify(ctx context.Context, username, password string) error {
	if v.cfg.Validator != nil {
		return v.verifyCustom(ctx, username, password)
	}
	return v.verifyUsers(username, password)
}

// Realm returns the configured authentication realm.
func (v *Verifier) Realm() string {
	return v.cfg.Realm
}

func (v *Verifier) verifyCustom(ctx context.Context, username, password string) error {
	ok, err := v.cfg.Validator(ctx, username, password)
	if err != nil {
		return fmt.Errorf("basic auth validator: %w", err)
	}
	if !ok {
		return ErrInvalidCredentials
	}
	return nil
}

func (v *Verifier) verifyUsers(username, password string) error {
	hashedPassword, exists := v.cfg.Users[username]
	if !exists {
		// Timing attack mitigation: always perform a bcrypt comparison even
		// when the user does not exist, so that the response time is consistent
		// regardless of whether the username is valid.
		_ = bcrypt.CompareHashAndPassword(v.dummyHash, []byte(password))
		return ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}
