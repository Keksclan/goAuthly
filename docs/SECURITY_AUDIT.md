# Security Audit Checklist

> **This library does NOT issue tokens.** goAuthly is a verification-only library.
> It does not issue, sign, refresh, or revoke tokens. It does not manage sessions or store credentials.

---

## Timing Attack Mitigation

| Path | Mitigation |
|------|-----------|
| **JWT verification** | Signature verification uses Go's `crypto/rsa` and `crypto/ecdsa`, which perform constant-time comparisons. |
| **Opaque token introspection** | Timing depends on the external introspection server. Cached responses return in constant time via Ristretto. |
| **Basic Auth** | `bcrypt.CompareHashAndPassword` is constant-time. When the username does not exist, a dummy bcrypt comparison is executed to prevent user-enumeration via response timing. |

**Recommendation:** Do not add early-return shortcuts in middleware wrapping goAuthly. Any short-circuit before the crypto comparison can reintroduce timing side channels.

---

## Timeout Enforcement

All network and script execution paths enforce timeouts:

| Component | Default | Configurable | Mechanism |
|-----------|---------|-------------|-----------|
| JWKS HTTP fetch | 5 s | `http.Client.Timeout` | Context propagation + `http.Client` deadline |
| Introspection HTTP call | 5 s | `IntrospectionConfig.Timeout` | Context propagation + `http.Client` deadline |
| Lua policy evaluation | 5 s | `EvaluateWithTimeout` / `EvaluateWithLimits` | `context.WithTimeout` checked on every VM instruction cycle |
| Lua instruction limit | 1 000 000 instructions (≈ 50 ms effective) | `EvaluateWithLimits(maxInstructions)` | Converted to a time budget (`instructionBudgetPerUnit` × `DefaultMaxInstructions` = 50 ns × 1 000 000 = **50 ms**) applied as an inner context deadline |

The instruction budget of **50 ms** is far stricter than the 5 s `EvaluateWithTimeout` wall-clock timeout. In practice, `EvaluateWithLimits` (and by extension `EvaluateWithTimeout`, which delegates to it) will be preempted by the instruction budget well before the wall-clock timeout fires, making the instruction count the dominant guard for typical scripts.

If a Lua script exceeds its limit, the request is **denied** with `ErrLuaTimeout` or `ErrLuaInstructionLimit`. Panics inside Lua evaluation are recovered and returned as `ErrLuaPanic`.

---

## JWT Hardening Rules

1. **Algorithm restriction** — Always set `AllowedAlgs` (e.g., `["RS256", "ES256"]`). The validator passes them via `WithValidMethods` and the keyfunc rejects key-type mismatches as defense-in-depth.
2. **No `"none"` algorithm** — The `"none"` value exists only for `ClientAuthKind` (introspection auth), never for JWT signature validation.
3. **`kid` required** — When JWKS is enabled, tokens without a `kid` header are rejected.
4. **Key type restriction** — Only RSA and ECDSA public keys are accepted from JWKS endpoints.
5. **Issuer / Audience validation** — Always configure `Issuer` and `Audience` (or `AudienceRule`). The validator rejects mismatches with generic error messages that do not leak expected values.
6. **Audience blocklist** — `AudienceRule.Blocklist` is evaluated before any allow logic. Deny rules cannot be bypassed by permissive allow rules.

---

## Opaque Token Caching Strategy

- Cache keys are **SHA-256 hashes** of the raw token concatenated with the introspection endpoint. The plaintext token is never stored.
- Only **active** introspection responses are cached. Inactive responses are not cached to avoid stale-positive scenarios.
- The Ristretto cache has a bounded `MaxCost` (1 MB default) to prevent unbounded memory growth.
- Cache TTL is configurable via `IntrospectionCacheTTL`.
- **Singleflight** coalesces concurrent introspection requests for the same token, preventing thundering-herd amplification.

---

## JWKS Size Limits

| Limit | Value | Location |
|-------|-------|----------|
| JWKS HTTP response body | 1 MB | `Manager.fetchSet` — `io.LimitReader(resp.Body, maxJWKSResponseSize)` |
| JWKS provider response body | 1 MB | `HTTPProvider.LoadFromURL` — same `io.LimitReader` guard |
| Introspection response body | 1 MB | `introspect.Client` — `io.LimitReader` on response |

Responses exceeding 1 MB are truncated, causing a JSON decode error and a denied request.

---

## Lua Policy Security

- Lua policies must be treated as **trusted configuration**. Only load scripts from sources you control (config files, CI pipelines). Never allow untrusted user input to define policy scripts.
- The Lua sandbox disables `os`, `io`, `debug`, and `package` libraries. `dofile`, `loadfile`, `load`, and `loadstring` are removed.
- Execution is bounded by both a timeout and an instruction-count limit. Infinite loops are terminated and return a safe error.
- Panic recovery wraps all Lua evaluation — no panic propagates to the caller.

---

## Recommendations for Production Deployment

1. **Use HTTPS** for all JWKS and introspection URLs. The library does not enforce HTTPS to avoid breaking local development, but production traffic must be encrypted.
2. **Store credentials in a vault** — `ClientID`, `ClientSecret`, and Basic Auth bcrypt hashes should come from environment variables or a secrets manager, never hardcoded.
3. **Restrict algorithms** — Set `AllowedAlgs` to only the algorithms your identity provider actually uses.
4. **Set `RequireActive: true`** for opaque tokens (this is the default).
5. **Configure audience rules** — Use `AudienceRule.Blocklist` to deny audiences that should never appear in tokens reaching your service.
6. **Set claim policies** — Use `Required`, `Denylist`, and `Allowlist` to enforce a strict claim surface.
7. **Enable `AllowStaleJWKS`** — This lets the verifier survive temporary JWKS endpoint outages without rejecting all requests.
8. **Prefer body transport** for introspection (`TokenTransportBody`). Tokens in headers are more likely to appear in access logs and proxy caches.
9. **Do not call `panic()`** in middleware wrapping goAuthly. A panic in an auth path can become a DoS vector or a security bypass.
10. **Review Lua policies** before deployment. Treat them with the same scrutiny as application code.

---

## Production Configuration Checklist

- [ ] `Issuer` and `Audience` (or `AudienceRule`) match your identity provider.
- [ ] `AudienceRule.Blocklist` denies any audiences that should never be accepted.
- [ ] `AllowedAlgs` is restricted to algorithms you actually use.
- [ ] JWKS URL uses HTTPS.
- [ ] Introspection endpoint uses HTTPS.
- [ ] Client credentials come from environment variables or a vault.
- [ ] `RequireActive` is `true` for opaque tokens.
- [ ] Claim policies reject unexpected claims via `Allowlist` / `Denylist`.
- [ ] Basic Auth passwords are bcrypt hashes, never plaintext.
- [ ] Actor policy (if used) has `AllowedActorSubjects` set.
- [ ] Lua policies are loaded from trusted sources only.
- [ ] Required metadata headers are configured when upstream gateway headers are expected.
