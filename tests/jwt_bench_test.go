package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	oauthjwt "github.com/keksclan/goAuthly/internal/oauth/jwt"
)

// ---------- helpers ----------

func mustRSAKey(b testing.TB) (*rsa.PrivateKey, *rsa.PublicKey) {
	b.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	return priv, &priv.PublicKey
}

func signToken(b testing.TB, priv *rsa.PrivateKey, kid string, claims gojwt.MapClaims) string {
	b.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		b.Fatal(err)
	}
	return s
}

// testMetrics is a thread-safe MetricsCollector for tests.
type testMetrics struct {
	ok      atomic.Int64
	failed  atomic.Int64
	reasons sync.Map // reason -> *atomic.Int64
}

func (m *testMetrics) ValidationOK() { m.ok.Add(1) }
func (m *testMetrics) ValidationFailed(reason string) {
	m.failed.Add(1)
	v, _ := m.reasons.LoadOrStore(reason, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}
func (m *testMetrics) reasonCount(reason string) int64 {
	v, ok := m.reasons.Load(reason)
	if !ok {
		return 0
	}
	return v.(*atomic.Int64).Load()
}

// ---------- Benchmarks Part 1: JWT Validate ----------

func BenchmarkJWTValidate_Valid(b *testing.B) {
	priv, pub := mustRSAKey(b)
	kid := "bench-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}
	cfg := oauthjwt.Config{
		Issuer:      "https://bench.test",
		Audience:    "api",
		AllowedAlgs: []string{"RS256"},
		JWKSEnabled: true,
	}
	v, err := oauthjwt.New(cfg, kp)
	if err != nil {
		b.Fatal(err)
	}
	token := signToken(b, priv, kid, gojwt.MapClaims{
		"iss":   "https://bench.test",
		"aud":   "api",
		"sub":   "user-1",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "read write",
	})
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Validate(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWTValidate_InvalidAudience(b *testing.B) {
	priv, pub := mustRSAKey(b)
	kid := "bench-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}
	cfg := oauthjwt.Config{
		Issuer:      "https://bench.test",
		Audience:    "correct-api",
		AllowedAlgs: []string{"RS256"},
		JWKSEnabled: true,
	}
	v, _ := oauthjwt.New(cfg, kp)
	token := signToken(b, priv, kid, gojwt.MapClaims{
		"iss": "https://bench.test",
		"aud": "wrong-api",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = v.Validate(ctx, token)
	}
}

func BenchmarkJWTValidate_InvalidIssuer(b *testing.B) {
	priv, pub := mustRSAKey(b)
	kid := "bench-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}
	cfg := oauthjwt.Config{
		Issuer:      "https://correct.test",
		Audience:    "api",
		AllowedAlgs: []string{"RS256"},
		JWKSEnabled: true,
	}
	v, _ := oauthjwt.New(cfg, kp)
	token := signToken(b, priv, kid, gojwt.MapClaims{
		"iss": "https://wrong.test",
		"aud": "api",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = v.Validate(ctx, token)
	}
}

func BenchmarkJWTValidate_Expired(b *testing.B) {
	priv, pub := mustRSAKey(b)
	kid := "bench-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}
	cfg := oauthjwt.Config{
		Issuer:      "https://bench.test",
		Audience:    "api",
		AllowedAlgs: []string{"RS256"},
		JWKSEnabled: true,
	}
	v, _ := oauthjwt.New(cfg, kp)
	token := signToken(b, priv, kid, gojwt.MapClaims{
		"iss": "https://bench.test",
		"aud": "api",
		"sub": "user-1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = v.Validate(ctx, token)
	}
}

func BenchmarkJWKSKeySelection(b *testing.B) {
	keys := make(map[string]any, 100)
	for i := range 100 {
		_, pub := mustRSAKey(b)
		keys[fmt.Sprintf("key-%d", i)] = pub
	}
	kp := &mockKeyProvider{keys: keys}
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = kp.GetKey(ctx, "key-50")
	}
}

// ---------- Benchmarks Part 2: Standard vs Throughput ----------

func BenchmarkValidate_Standard(b *testing.B) {
	benchValidateMode(b, oauthjwt.ValidatorModeStandard)
}

func BenchmarkValidate_Throughput(b *testing.B) {
	benchValidateMode(b, oauthjwt.ValidatorModeThroughput)
}

func benchValidateMode(b *testing.B, mode oauthjwt.ValidatorMode) {
	b.Helper()
	priv, pub := mustRSAKey(b)
	kid := "mode-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}
	cfg := oauthjwt.Config{
		Issuer:      "https://bench.test",
		Audience:    "api",
		AllowedAlgs: []string{"RS256"},
		JWKSEnabled: true,
		Mode:        mode,
	}
	v, err := oauthjwt.New(cfg, kp)
	if err != nil {
		b.Fatal(err)
	}
	token := signToken(b, priv, kid, gojwt.MapClaims{
		"iss":   "https://bench.test",
		"aud":   "api",
		"sub":   "user-1",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "read write admin",
	})
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Validate(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------- Concurrency test (Part 2) ----------

func TestValidateThroughput_Concurrent(t *testing.T) {
	priv, pub := mustRSAKey(t)
	kid := "conc-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}
	m := &testMetrics{}
	cfg := oauthjwt.Config{
		Issuer:      "https://conc.test",
		Audience:    "api",
		AllowedAlgs: []string{"RS256"},
		JWKSEnabled: true,
		Mode:        oauthjwt.ValidatorModeThroughput,
		Metrics:     m,
	}
	v, err := oauthjwt.New(cfg, kp)
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, priv, kid, gojwt.MapClaims{
		"iss":   "https://conc.test",
		"aud":   "api",
		"sub":   "user-1",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "read",
	})

	const goroutines = 100
	const iterations = 50
	ctx := t.Context()
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				claims, err := v.Validate(ctx, token)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if claims.Subject != "user-1" {
					t.Errorf("subject mismatch: %s", claims.Subject)
					return
				}
			}
		}()
	}
	wg.Wait()

	expectedOK := int64(goroutines * iterations)
	if m.ok.Load() != expectedOK {
		t.Errorf("expected %d ok, got %d", expectedOK, m.ok.Load())
	}
	if m.failed.Load() != 0 {
		t.Errorf("expected 0 failures, got %d", m.failed.Load())
	}
}

// ---------- Regression tests for fast-fail ordering ----------

func TestValidate_FastFailOrdering(t *testing.T) {
	priv, pub := mustRSAKey(t)
	kid := "ff-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}

	tests := []struct {
		name        string
		config      oauthjwt.Config
		claims      gojwt.MapClaims
		errContains string
	}{
		{
			name: "algorithm rejected first",
			config: oauthjwt.Config{
				Issuer:      "https://ff.test",
				Audience:    "api",
				AllowedAlgs: []string{"ES256"},
				JWKSEnabled: true,
			},
			claims: gojwt.MapClaims{
				"iss": "https://wrong.test",
				"aud": "wrong-api",
				"sub": "user-1",
				"exp": time.Now().Add(-time.Hour).Unix(),
			},
			errContains: "signing method",
		},
		{
			name: "missing kid rejected",
			config: oauthjwt.Config{
				Issuer:      "https://ff.test",
				Audience:    "api",
				JWKSEnabled: true,
			},
			claims: gojwt.MapClaims{
				"iss": "https://ff.test",
				"aud": "api",
				"sub": "user-1",
				"exp": time.Now().Add(time.Hour).Unix(),
			},
			errContains: "missing required kid",
		},
		{
			name: "issuer mismatch after signature",
			config: oauthjwt.Config{
				Issuer:      "https://correct.test",
				Audience:    "api",
				JWKSEnabled: true,
			},
			claims: gojwt.MapClaims{
				"iss": "https://wrong.test",
				"aud": "api",
				"sub": "user-1",
				"exp": time.Now().Add(time.Hour).Unix(),
			},
			errContains: "issuer mismatch",
		},
		{
			name: "audience blocked",
			config: oauthjwt.Config{
				Issuer: "https://ff.test",
				AudienceRule: oauthjwt.AudienceRule{
					AnyOf:     []string{"api"},
					Blocklist: []string{"blocked"},
				},
				JWKSEnabled: true,
			},
			claims: gojwt.MapClaims{
				"iss": "https://ff.test",
				"aud": "blocked",
				"sub": "user-1",
				"exp": time.Now().Add(time.Hour).Unix(),
			},
			errContains: "audience blocked",
		},
		{
			name: "expired token",
			config: oauthjwt.Config{
				Issuer:      "https://ff.test",
				Audience:    "api",
				JWKSEnabled: true,
			},
			claims: gojwt.MapClaims{
				"iss": "https://ff.test",
				"aud": "api",
				"sub": "user-1",
				"exp": time.Now().Add(-time.Hour).Unix(),
			},
			errContains: "expired",
		},
		{
			name: "iat in future",
			config: oauthjwt.Config{
				Issuer:      "https://ff.test",
				Audience:    "api",
				JWKSEnabled: true,
				ClockSkew:   5 * time.Second,
			},
			claims: gojwt.MapClaims{
				"iss": "https://ff.test",
				"aud": "api",
				"sub": "user-1",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(time.Hour).Unix(),
			},
			errContains: "issued in the future",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := oauthjwt.New(tt.config, kp)
			if err != nil {
				t.Fatal(err)
			}
			tokenStr := signToken(t, priv, kid, tt.claims)
			// For the missing kid test, create a token without kid header.
			if tt.name == "missing kid rejected" {
				tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, tt.claims)
				// Don't set kid header
				tokenStr, _ = tok.SignedString(priv)
			}
			_, err = v.Validate(t.Context(), tokenStr)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

// ---------- Metrics regression test ----------

func TestMetricsCollector(t *testing.T) {
	priv, pub := mustRSAKey(t)
	kid := "met-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}
	m := &testMetrics{}

	cfg := oauthjwt.Config{
		Issuer:      "https://met.test",
		Audience:    "api",
		AllowedAlgs: []string{"RS256"},
		JWKSEnabled: true,
		Metrics:     m,
	}
	v, _ := oauthjwt.New(cfg, kp)

	// Valid token.
	tok := signToken(t, priv, kid, gojwt.MapClaims{
		"iss": "https://met.test",
		"aud": "api",
		"sub": "u",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ctx := t.Context()
	if _, err := v.Validate(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if m.ok.Load() != 1 {
		t.Fatalf("expected 1 ok, got %d", m.ok.Load())
	}

	// Wrong issuer.
	tok2 := signToken(t, priv, kid, gojwt.MapClaims{
		"iss": "https://wrong.test",
		"aud": "api",
		"sub": "u",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, _ = v.Validate(ctx, tok2)
	if m.reasonCount(oauthjwt.FailReasonIssuer) != 1 {
		t.Fatalf("expected 1 issuer failure, got %d", m.reasonCount(oauthjwt.FailReasonIssuer))
	}

	// Expired.
	tok3 := signToken(t, priv, kid, gojwt.MapClaims{
		"iss": "https://met.test",
		"aud": "api",
		"sub": "u",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	_, _ = v.Validate(ctx, tok3)
	if m.reasonCount(oauthjwt.FailReasonExpired) != 1 {
		t.Fatalf("expected 1 expired failure, got %d", m.reasonCount(oauthjwt.FailReasonExpired))
	}
}

// ---------- Metrics: no double emission for keyfunc errors ----------

func TestMetricsCollector_NoDoubleEmission(t *testing.T) {
	priv, pub := mustRSAKey(t)
	kid := "dbl-key"
	kp := &mockKeyProvider{keys: map[string]any{kid: pub}}

	t.Run("missing kid emits exactly one failure", func(t *testing.T) {
		m := &testMetrics{}
		cfg := oauthjwt.Config{
			Issuer:      "https://dbl.test",
			Audience:    "api",
			AllowedAlgs: []string{"RS256"},
			JWKSEnabled: true,
			Metrics:     m,
		}
		v, err := oauthjwt.New(cfg, kp)
		if err != nil {
			t.Fatal(err)
		}

		// Create a token without kid header.
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{
			"iss": "https://dbl.test",
			"aud": "api",
			"sub": "u",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenStr, err := tok.SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}

		_, _ = v.Validate(t.Context(), tokenStr)
		if got := m.failed.Load(); got != 1 {
			t.Fatalf("expected exactly 1 failure metric, got %d", got)
		}
		if got := m.reasonCount(oauthjwt.FailReasonKid); got != 1 {
			t.Fatalf("expected 1 kid failure, got %d", got)
		}
		// Ensure no spurious parse failure was emitted.
		if got := m.reasonCount(oauthjwt.FailReasonParse); got != 0 {
			t.Fatalf("expected 0 parse failures, got %d", got)
		}
	})

	t.Run("algorithm mismatch emits exactly one failure", func(t *testing.T) {
		m := &testMetrics{}
		secret := []byte("super-secret-key-for-hmac-256-xx")
		hmacKP := &mockKeyProvider{keys: map[string]any{"hmac-kid": secret}}
		cfg := oauthjwt.Config{
			Issuer:      "https://dbl.test",
			Audience:    "api",
			AllowedAlgs: []string{"RS256"},
			JWKSEnabled: true,
			Metrics:     m,
		}
		v, err := oauthjwt.New(cfg, hmacKP)
		if err != nil {
			t.Fatal(err)
		}

		// Sign with HS256 while only RS256 is allowed.
		tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
			"iss": "https://dbl.test",
			"aud": "api",
			"sub": "u",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = "hmac-kid"
		tokenStr, err := tok.SignedString(secret)
		if err != nil {
			t.Fatal(err)
		}

		_, _ = v.Validate(t.Context(), tokenStr)
		if got := m.failed.Load(); got != 1 {
			t.Fatalf("expected exactly 1 failure metric, got %d", got)
		}
		if got := m.reasonCount(oauthjwt.FailReasonAlg); got != 1 {
			t.Fatalf("expected 1 alg failure, got %d", got)
		}
		if got := m.reasonCount(oauthjwt.FailReasonParse); got != 0 {
			t.Fatalf("expected 0 parse failures, got %d", got)
		}
	})
}

// ---------- IndexedKeyProvider test ----------

func TestIndexedKeyProvider(t *testing.T) {
	_, pub1 := mustRSAKey(t)
	_, pub2 := mustRSAKey(t)
	inner := &mockKeyProvider{keys: map[string]any{"k1": pub1}}

	idx := oauthjwt.NewIndexedKeyProvider(inner)

	// Before index is built, fallback to inner.
	key, err := idx.GetKey(t.Context(), "k1")
	if err != nil {
		t.Fatal(err)
	}
	if key != pub1 {
		t.Fatal("expected pub1")
	}

	// Build index with k2.
	idx.RebuildIndex(map[string]any{"k2": pub2})

	// k2 from index.
	key, err = idx.GetKey(t.Context(), "k2")
	if err != nil {
		t.Fatal(err)
	}
	if key != pub2 {
		t.Fatal("expected pub2")
	}

	// k1 falls back to inner.
	key, err = idx.GetKey(t.Context(), "k1")
	if err != nil {
		t.Fatal(err)
	}
	if key != pub1 {
		t.Fatal("expected pub1 from fallback")
	}

	// Unknown key fails.
	_, err = idx.GetKey(t.Context(), "unknown")
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}
