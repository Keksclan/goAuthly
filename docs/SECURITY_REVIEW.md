# Security Review — 2026-02-20

Full repository scan of `github.com/Keksclan/goAuthly`.

## Findings

### Sensitive Data Handling

| Finding | Severity | Fix Applied | Notes |
|---------|----------|-------------|-------|
| Library code does not log tokens, Authorization headers, or raw claims | — | N/A | ✅ Verified across all packages |
| Example code prints JWT tokens to stdout | Low | No | Acceptable for example/demo programs |
| Error messages no longer leak issuer values (was `"invalid issuer: expected X, got Y"`) | Med | Yes (prior commit) | Changed to `"token issuer mismatch"` |

### DoS & Resource Limits

| Finding | Severity | Fix Applied | Notes |
|---------|----------|-------------|-------|
| `Manager.fetchSet` limits JWKS response to 1 MB via `io.LimitReader` | — | N/A | ✅ Already present |
| `HTTPProvider.LoadFromURL` was missing `LimitReader` on JWKS response body | Med | Yes | Added `io.LimitReader(resp.Body, maxJWKSResponseSize)` |
| Introspection client limits response to 1 MB | — | N/A | ✅ Already present |
| HTTP clients have mandatory timeouts (5s JWKS, configurable introspection) | — | N/A | ✅ Verified |
| Context propagation used in all network calls | — | N/A | ✅ Verified |

### Panic Safety

| Finding | Severity | Fix Applied | Notes |
|---------|----------|-------------|-------|
| No `panic()` calls in library code | — | N/A | ✅ Only in example code (acceptable) |
| Existing `no_panic_test.go` covers panic regression | — | N/A | ✅ Verified |

### Crypto Correctness

| Finding | Severity | Fix Applied | Notes |
|---------|----------|-------------|-------|
| Algorithms explicitly allowed via `WithValidMethods` + keyfunc defense-in-depth | — | N/A | ✅ |
| No `"none"` algorithm acceptance — `"none"` is only used for `ClientAuthKind` (unrelated to JWT signing) | — | N/A | ✅ |
| `kid` required when JWKS enabled | — | N/A | ✅ Enforced in keyfunc |
| Key types restricted to RSA and ECDSA public keys | — | N/A | ✅ |
| Basic auth uses bcrypt with timing-attack mitigation (dummy hash for unknown users) | — | N/A | ✅ |

### Caching Security

| Finding | Severity | Fix Applied | Notes |
|---------|----------|-------------|-------|
| Introspection cache keys use SHA-256 hash of token (no plaintext) | — | N/A | ✅ |
| Ristretto cache has bounded `MaxCost` (1 MB default) | — | N/A | ✅ Prevents unbounded growth |
| Only active introspection responses are cached | — | N/A | ✅ |
| JWKS cache uses configurable TTL with stale fallback | — | N/A | ✅ |
| Singleflight prevents JWKS stampede on cache miss | — | N/A | ✅ |

### SSRF / URL Validation

| Finding | Severity | Fix Applied | Notes |
|---------|----------|-------------|-------|
| No HTTPS enforcement on JWKS or introspection URLs | Low | No | Documented in `docs/security.md` checklist. Enforcing HTTPS in library would break local development; users should use HTTPS in production. |
| No localhost/private-range blocking | Low | No | Would be overly restrictive for legitimate dev/test environments. Documented as user responsibility. |

### Error Messages

| Finding | Severity | Fix Applied | Notes |
|---------|----------|-------------|-------|
| Validator errors are generic (no claim values leaked) | — | N/A | ✅ e.g. `"token issuer mismatch"` not `"expected X got Y"` |
| `jwt_hardened_test.go` verifies no subject/issuer leakage in errors | — | N/A | ✅ |

## Summary

- **High severity issues**: None found.
- **Medium severity issues**: 2 found, both fixed.
  1. Error messages previously leaked expected/actual issuer values (fixed in prior commit).
  2. `HTTPProvider.LoadFromURL` missing response size limit (fixed in this review).
- **Low severity issues**: 2 found, documented but not fixed (HTTPS enforcement, private-range blocking) — by design to avoid breaking dev workflows.
- **Repository remains lightweight**: No new dependencies added.
