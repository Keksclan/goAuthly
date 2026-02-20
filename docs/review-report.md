# Engineering Review Report — goAuthly

<p align="center"><img src="../img.png" alt="Schnallbert" width="128" /><br/><em>Schnallbert says: "Even bouncers get reviewed — transparency matters!"</em></p>

**Date:** 2026-02-20
**Reviewer:** Junie (automated)
**Scope:** Correctness, Security, Performance

---

## 1. Executive Summary

The goAuthly codebase is well-structured with clean separation of concerns, proper error typing, and good concurrency design. The review identified **5 actionable issues** — 2 security, 1 correctness, 1 performance, and 1 sandbox hardening — all of which have been fixed and tested. No new features were added; all changes are minimal and targeted.

---

## 2. Correctness Findings

### 2.1 Empty token accepted by `Engine.Verify` (FIXED)

**Severity:** Medium
**File:** `authly/engine.go`

When an adapter passed an empty string (e.g., `"Bearer "` with nothing after the space), `Engine.Verify` would proceed to classify it via `strings.Count("", ".") == 2` (false), then attempt introspection or reject as invalid token depending on mode. While not a bypass (it would fail downstream), the error message was confusing and the empty string should be rejected early.

**Fix:** Added an explicit `token == ""` check at the top of `Verify()` that returns `ErrInvalidToken`.
**Test:** `TestVerify_EmptyToken`, `TestVerify_WhitespaceToken`

### 2.2 Verification paths reviewed — no other issues

All verification paths (JWT-only, opaque-only, JWT+opaque, basic auth) were reviewed:
- Malformed tokens: correctly rejected.
- Missing `kid`: results in `ErrKeyNotFound` from JWKS manager — correct.
- Unsupported alg: rejected by JWT validator's `AllowedAlgs` check.
- Invalid issuer/audience: rejected by JWT validator and audience rules.
- JWKS fetch failures: properly wrapped errors, stale fallback works when configured.
- Introspection failures: 401/500 return wrapped errors; inactive tokens respected per `OpaquePolicy`.
- Lua policy errors: syntax errors caught at compile time, runtime errors wrapped properly.
- Concurrency: caches (ristretto) are concurrent-safe; JWKS manager uses proper patterns; Lua `CompiledPolicy` uses mutex correctly; `Engine` has no mutable shared state after construction.

---

## 3. Security Findings

### 3.1 Unbounded HTTP response reads (FIXED)

**Severity:** High
**Files:** `internal/oauth/introspect/client.go`, `internal/jwk/manager.go`

Both the introspection client and JWKS manager read HTTP response bodies without size limits. A malicious or compromised server could send a multi-GB response and exhaust memory (memory bomb / DoS).

**Fix:** Wrapped `resp.Body` with `io.LimitReader(resp.Body, 1<<20)` (1 MB limit) in both locations. This is generous for JWKS (typically <100KB) and introspection responses (typically <10KB).
**Tests:** `TestIntrospection_OversizedResponse`, `TestJWKS_OversizedResponse`

### 3.2 Lua sandbox: `loadstring` not removed (FIXED)

**Severity:** Medium
**Files:** `internal/luaengine/engine.go`, `authlyconfig/loader.go`

The Lua sandbox correctly removed `dofile`, `loadfile`, and `load` from the base library, but missed `loadstring`. In gopher-lua, `loadstring` is a separate global that allows compiling arbitrary Lua code at runtime. While it can't escape the Go process, it could be used to dynamically generate code that circumvents static policy analysis.

**Fix:** Added `L.SetGlobal("loadstring", lua.LNil)` in both `openSafeLibs()` (policy engine) and `LoadLuaString()` (config loader).
**Test:** `TestLuaSandbox_LoadstringBlocked`

### 3.3 Items verified as safe (no fix needed)

- **Token hashing:** Opaque tokens are hashed with SHA-256 + hex encoding for cache keys — correct.
- **No raw tokens in logs:** Library does not log tokens.
- **Type assertions:** All use type switches or comma-ok pattern — no panic risk.
- **Actor claim parsing:** Uses safe type switches; cannot bypass checks.
- **Audience rules:** Blocklist is checked first (always wins); encoding is compared as exact strings — safe.
- **HTTP timeouts:** Default client has 10s timeout; introspection client sets per-config timeout.
- **Basic Auth:** Uses bcrypt (constant-time); dummy hash comparison for unknown users prevents enumeration.
- **Lua sandbox:** `os`, `io`, `debug`, `package` libraries are not loaded (`SkipOpenLibs: true`). Context-based timeout (checked every ~100 VM instructions) prevents infinite loops.
- **Adapter safety:** Required metadata validation occurs before auth; errors don't leak secrets.
- **Lua memory:** gopher-lua doesn't support memory limits. Documented as a known limitation (see §6).

---

## 4. Performance Findings

### 4.1 JWKS fetch stampede on cache miss (FIXED)

**Severity:** Medium
**File:** `internal/jwk/manager.go`

When the JWKS cache entry expires, every concurrent request hitting `GetKey` would independently fetch the JWKS endpoint. Under load, this causes a "thundering herd" / cache miss stampede with potentially hundreds of redundant HTTP requests.

**Fix:** Added `golang.org/x/sync/singleflight` to `Manager`. Concurrent calls for the same JWKS URL now coalesce into a single HTTP fetch. Includes a double-check of the cache inside the singleflight callback to handle the race where another goroutine just populated it.
**Test:** `TestJWKS_SingleflightDedup` (fires 10 concurrent requests, verifies <5 actual fetches)

**Dependency justification:** `golang.org/x/sync/singleflight` is the standard Go solution for this pattern. It's a single-file package from the Go team with no transitive dependencies.

### 4.2 Items reviewed — no bottleneck found

- **Token parsing:** Done once per request — acceptable.
- **Audience normalization:** `AudienceRule.Validate` builds a map per call, but audience lists are typically small (<10 entries). Not a bottleneck.
- **Introspection caching:** Active tokens are cached with configurable TTL. SHA-256 hashing for cache keys is fast (~200ns).
- **Ristretto usage:** Costs are set to 1 (appropriate for count-based eviction). TTL is used correctly. `Wait()` is called after cache writes for immediate visibility — correct pattern.
- **Lua policy:** A new `LState` is created per evaluation (required for safety due to global state). The compiled `FunctionProto` is reused. The mutex serializes evaluations, which is acceptable for policy checks.

### 4.3 Micro-benchmarks added

**File:** `tests/bench_verify_test.go`

| Benchmark | What it measures |
|---|---|
| `BenchmarkVerifyJWT` | Full JWT verification with cached JWKS (hot path) |
| `BenchmarkLuaPolicyEvaluate` | Lua VM setup + policy evaluation per request |
| `BenchmarkAudienceValidate` | Audience rule matching with AllOf + AnyOf + Blocklist |
| `BenchmarkIntrospectionCacheKey` | Opaque token verify path (exercises SHA-256 cache key) |

---

## 5. Changes Implemented

| File | Change |
|---|---|
| `internal/oauth/introspect/client.go` | Added `io.LimitReader` (1 MB) on response body read |
| `internal/jwk/manager.go` | Added `io.LimitReader` (1 MB) on JWKS response; added `singleflight.Group` to deduplicate concurrent fetches |
| `internal/luaengine/engine.go` | Removed `loadstring` from Lua sandbox globals |
| `authlyconfig/loader.go` | Removed `loadstring` from config loader Lua sandbox |
| `authly/engine.go` | Added early `token == ""` check in `Verify()` |
| `tests/review_fixes_test.go` | **New:** 8 tests covering all fixes |
| `tests/bench_verify_test.go` | **New:** 4 micro-benchmarks |
| `docs/review-report.md` | **New:** This report |
| `go.mod` / `go.sum` | Added `golang.org/x/sync` dependency |

---

## 6. Remaining Risks / TODOs

1. **Lua memory limit:** gopher-lua does not support memory allocation limits. A malicious Lua policy script could allocate large tables until OOM. The context timeout mitigates this partially (script is killed after 5s), but a determined attacker could allocate ~GB in that window. **Mitigation:** Document that Lua policy scripts must be trusted; consider adding a process-level memory watchdog in production.

2. **SSRF on JWKS/Introspection URLs:** The library fetches URLs provided in configuration. If an attacker can control config values, they could point to internal services. **Mitigation:** URLs come from static configuration, not from tokens or user input. Document that operators must validate their config URLs.

3. **Introspection singleflight:** Unlike JWKS, introspection calls are per-token (cache key includes token hash), so singleflight would only help if the exact same token is verified concurrently. This is less common, so singleflight was not added for introspection. If needed in the future, it can be added to `cachedIntrospect`.
