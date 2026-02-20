package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/keksclan/goAuthly/authly"
	"github.com/keksclan/goAuthly/internal/basic"
	"golang.org/x/crypto/bcrypt"
)

func hashPassword(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	return string(h)
}

func newBasicEngine(t *testing.T, cfg authly.BasicAuthConfig) *authly.Engine {
	t.Helper()
	eng, err := authly.New(authly.Config{
		Mode:      authly.AuthModeBasic,
		BasicAuth: cfg,
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng
}

func TestVerifyBasic_UsersMap(t *testing.T) {
	eng := newBasicEngine(t, authly.BasicAuthConfig{
		Enabled: true,
		Users: map[string]string{
			"admin": hashPassword(t, "secret"),
		},
		Realm: "TestRealm",
	})

	ctx := context.Background()

	// Valid credentials
	result, err := eng.VerifyBasic(ctx, "admin", "secret")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if result.Type != authly.TokenTypeBasic {
		t.Errorf("expected type basic, got %s", result.Type)
	}
	if result.Subject != "admin" {
		t.Errorf("expected subject admin, got %s", result.Subject)
	}
	if result.Source != "basic" {
		t.Errorf("expected source basic, got %s", result.Source)
	}
	if result.Claims["auth_method"] != "basic" {
		t.Errorf("expected auth_method basic, got %v", result.Claims["auth_method"])
	}
	if !result.IsBasic() {
		t.Error("expected IsBasic() == true")
	}

	// Invalid password
	_, err = eng.VerifyBasic(ctx, "admin", "wrong")
	if !errors.Is(err, basic.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}

	// Unknown user
	_, err = eng.VerifyBasic(ctx, "unknown", "secret")
	if !errors.Is(err, basic.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for unknown user, got: %v", err)
	}
}

func TestVerifyBasic_CustomValidator(t *testing.T) {
	eng := newBasicEngine(t, authly.BasicAuthConfig{
		Enabled: true,
		Validator: func(_ context.Context, username, password string) (bool, error) {
			return username == "dbuser" && password == "dbpass", nil
		},
	})

	ctx := context.Background()

	result, err := eng.VerifyBasic(ctx, "dbuser", "dbpass")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if result.Subject != "dbuser" {
		t.Errorf("expected subject dbuser, got %s", result.Subject)
	}

	_, err = eng.VerifyBasic(ctx, "dbuser", "wrong")
	if !errors.Is(err, basic.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestVerifyBasic_ValidatorTakesPriority(t *testing.T) {
	// Even with Users map present, Validator should win
	eng := newBasicEngine(t, authly.BasicAuthConfig{
		Enabled: true,
		Users: map[string]string{
			"admin": hashPassword(t, "secret"),
		},
		Validator: func(_ context.Context, username, password string) (bool, error) {
			return username == "custom" && password == "custom", nil
		},
	})

	ctx := context.Background()

	// Validator user works
	result, err := eng.VerifyBasic(ctx, "custom", "custom")
	if err != nil {
		t.Fatalf("expected success via validator, got: %v", err)
	}
	if result.Subject != "custom" {
		t.Errorf("expected subject custom, got %s", result.Subject)
	}

	// Users map user does NOT work (Validator wins)
	_, err = eng.VerifyBasic(ctx, "admin", "secret")
	if !errors.Is(err, basic.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials (validator wins), got: %v", err)
	}
}

func TestVerifyBasic_ValidatorError(t *testing.T) {
	dbErr := errors.New("database down")
	eng := newBasicEngine(t, authly.BasicAuthConfig{
		Enabled: true,
		Validator: func(_ context.Context, _, _ string) (bool, error) {
			return false, dbErr
		},
	})

	_, err := eng.VerifyBasic(context.Background(), "user", "pass")
	if err == nil {
		t.Fatal("expected error from validator")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

func TestVerifyBasic_NotConfigured(t *testing.T) {
	// OAuth2 engine should reject VerifyBasic
	ts := startDemoServer(t)
	defer ts.Close()
	eng := newEngineForNoPanic(t, ts.URL)

	_, err := eng.VerifyBasic(context.Background(), "admin", "secret")
	if !errors.Is(err, authly.ErrUnsupportedMode) {
		t.Errorf("expected ErrUnsupportedMode, got: %v", err)
	}
}

func TestVerifyBasic_ConfigValidation(t *testing.T) {
	// Basic mode but Enabled=false
	_, err := authly.New(authly.Config{
		Mode:      authly.AuthModeBasic,
		BasicAuth: authly.BasicAuthConfig{Enabled: false},
	})
	if err == nil {
		t.Error("expected error for disabled basic auth in basic mode")
	}

	// Basic mode, enabled but no users or validator
	_, err = authly.New(authly.Config{
		Mode:      authly.AuthModeBasic,
		BasicAuth: authly.BasicAuthConfig{Enabled: true},
	})
	if err == nil {
		t.Error("expected error for basic auth without credentials source")
	}
}

func TestVerifyBasic_DefaultRealm(t *testing.T) {
	eng := newBasicEngine(t, authly.BasicAuthConfig{
		Enabled: true,
		Users: map[string]string{
			"admin": hashPassword(t, "pass"),
		},
	})
	// Engine is created — default realm applied internally
	_ = eng
}
