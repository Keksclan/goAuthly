# Audit Summary

**Date:** 2026-02-20
**Scope:** Full repository code review (security, correctness, performance)

---

## Issues Found

### 1. Potential Panic Path — Unchecked Type Assertion in JWK Manager
- **File:** `internal/jwk/manager.go:96`
- **Severity:** High
- **Description:** The `singleflight.Do` result was cast to `jwk.Set` via a bare type assertion (`result.(jwk.Set)`). If the singleflight callback returned an unexpected type (e.g., due to a race or upstream change), this would panic and crash the process.

### 2. Missing Error Wrapping — Audience Validation in JWT Validator
- **File:** `internal/oauth/jwt/validator.go` (validateAudience method)
- **Severity:** Medium
- **Description:** Audience validation errors were returned as bare `fmt.Errorf("audience blocked")` / `fmt.Errorf("audience not allowed")` strings without wrapping sentinel errors. This prevented callers from using `errors.Is()` for reliable error classification.

---

## Fixes Applied

### 1. Safe Type Assertion in JWK Manager (manager.go:96)
- Converted bare `result.(jwk.Set)` to a comma-ok assertion: `set, ok := result.(jwk.Set)`.
- Returns a descriptive error instead of panicking when the type is unexpected.

### 2. Sentinel Error Wrapping in JWT Validator (validator.go)
- Added `ErrAudienceBlocked` and `ErrAudienceNotAllowed` sentinel errors to the `internal/oauth/jwt` package.
- Changed all audience error returns to use `fmt.Errorf("%w", ErrAudienceBlocked)` and `fmt.Errorf("%w", ErrAudienceNotAllowed)`.
- Callers can now use `errors.Is()` for reliable matching.

### 3. Unit Tests Added
- `tests/audit_fixes_test.go` — Tests sentinel error definitions, error messages, and validator construction with audience rules.

---

## Remaining Risks

| Risk | Severity | Notes |
|------|----------|-------|
| Client secrets in config structs | Low | Secrets (ClientSecret, Password) are held in memory as plain strings. No logging of these values was found, but callers must ensure configs are not serialized to logs. |
| No rate limiting on introspection | Low | The introspection client has timeouts and response size limits but no per-endpoint rate limiting. Upstream throttling is assumed. |
| Lua policy sandbox | Low | The Lua engine uses gopher-lua which is sandboxed by default, but custom scripts could consume CPU. The existing timeout mechanism mitigates this, and the PR introduces an instruction-count cap (`DefaultMaxInstructions`) which triggers `ErrLuaInstructionLimit` when exceeded, providing a second defense against CPU exhaustion by limiting executed Lua instructions. |
| Cache eviction under memory pressure | Info | The Ristretto cache has a configurable max cost, but extremely high traffic with unique tokens could cause eviction churn. |

---

## Recommended Next Improvements

1. **Structured logging interface** — Add an optional `slog.Logger` field to Config so callers can capture internal warnings (e.g., JWKS fetch failures) without resorting to `fmt` output.
2. **Secret redaction** — Implement a `fmt.Stringer`/`GoStringer` on config types that redacts `ClientSecret` and `Password` fields to prevent accidental logging.
3. **JWKS key rotation metrics** — Expose key rotation events through the existing `MetricsCollector` interface so operators can detect stale keys.
4. **Fuzz testing** — Add `testing.F` fuzz targets for JWT parsing and audience rule validation to catch edge cases in untrusted input handling.
5. **golangci-lint CI integration** — Enforce `errcheck`, `gosec`, and `govet` linters in CI to catch future regressions automatically.
