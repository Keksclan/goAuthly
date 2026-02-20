# Performance

<p align="center"><img src="../img.png" alt="Schnallbert" width="128" /><br/><em>Schnallbert says: "Fast auth means happy users — don't slow down the gate!"</em></p>

goAuthly is designed for the hot path. Every request that hits your service goes through auth verification, so it needs to be fast. Here's how it works under the hood and how to tune it.

---

## Cache Strategy

### JWKS Caching

JWKS keys are fetched over HTTP and cached in memory.

| Setting | Default | Description |
|---------|---------|-------------|
| `JWKSCacheTTL` | 15 min | How long keys are considered fresh |
| `AllowStaleJWKS` | false | Serve stale keys if refresh fails |

When `AllowStaleJWKS` is true, a stale copy is kept at 4× TTL (minimum 1 hour). If the JWKS endpoint is down, stale keys are served instead of failing every request. This is a resilience trade-off: you accept slightly outdated keys to avoid downtime.

**Tuning:** If your IdP rotates keys infrequently, increase `JWKSCacheTTL` to 1 hour. If it rotates frequently, keep it at 5–15 minutes.

### Introspection Caching

Introspection responses are cached briefly to reduce load on the IdP.

| Setting | Default | Description |
|---------|---------|-------------|
| `IntrospectionCacheTTL` | 30 sec | How long active responses are cached |

Only **active** responses are cached. Inactive or error responses are not cached — this ensures revoked tokens are detected quickly.

Cache keys are SHA-256 hashes of the token plus the endpoint URL. Raw tokens never appear in cache keys or values.

**Tuning:** For high-traffic services, 30–60 seconds is a good balance. Lower values increase IdP load but improve revocation detection speed.

### Basic Auth

Basic Auth does **not** use caching. Every call to `VerifyBasic` performs a fresh bcrypt comparison (or calls the custom Validator). This is intentional:

- bcrypt is designed to be slow (~60ms at default cost). Caching would bypass this intentional slowness.
- Credential changes should take effect immediately.
- The bcrypt cost is the rate limiter against brute-force attacks.

If bcrypt latency is a concern for your use case, consider using a custom `Validator` with your own caching strategy. But think carefully — caching credentials introduces a revocation delay.

---

## Hot Paths

### Token Type Detection

```
Token → count "." → 2 dots? → JWT path
                  → else   → Opaque path
```

This is O(1) with zero allocations. No parsing, no regex, no base64 decoding.

### JWT Verification

1. Parse the JWT header to extract `kid` and `alg`.
2. Look up the key in the JWKS cache (in-memory map lookup).
3. Verify the signature using `crypto/rsa` or `crypto/ecdsa`.
4. Validate standard claims: `iss`, `aud`, `exp`, `nbf`.

Steps 1–2 are fast. Step 3 is the expensive part (~0.1–0.5ms for RSA-2048).

### Opaque Token Verification

1. Compute SHA-256 hash of the token (cache key).
2. Check the in-memory cache.
3. On cache miss: HTTP POST to the introspection endpoint.
4. Cache the response if active.

Step 3 dominates. A cache hit returns in microseconds.

### Basic Auth Verification

1. Look up username in the `Users` map.
2. bcrypt comparison (~60ms at default cost).

Step 2 dominates by design. This is a feature, not a bug.

---

## How to Benchmark

### Simple Go Benchmark

```go
func BenchmarkVerifyJWT(b *testing.B) {
    engine := setupEngine() // your setup
    token := mintValidJWT() // your token
    ctx := context.Background()

    b.ResetTimer()
    for b.Loop() {
        _, _ = engine.Verify(ctx, token)
    }
}

func BenchmarkVerifyBasic(b *testing.B) {
    engine := setupBasicEngine()
    ctx := context.Background()

    b.ResetTimer()
    for b.Loop() {
        _, _ = engine.VerifyBasic(ctx, "admin", "password")
    }
}
```

Run with:

```bash
go test -bench=BenchmarkVerify -benchmem -count=5
```

### What to Look For

| Metric | JWT (cached JWKS) | Opaque (cache hit) | Opaque (cache miss) | Basic Auth |
|--------|-------------------|--------------------|--------------------|------------|
| Latency | ~0.1–0.5ms | ~1–10μs | ~5–50ms (network) | ~60ms (bcrypt) |
| Allocs | ~5–10 | ~1–2 | ~10–20 | ~2–3 |

---

## How to Scale Horizontally

goAuthly is stateless by design. Each Engine instance has its own in-memory cache, so scaling is straightforward:

1. **Multiple instances:** Each instance independently fetches JWKS and caches introspection responses. No coordination needed.

2. **Shared cache:** If you want to share introspection cache across instances, implement the `Cache` interface backed by Redis or Memcached. Pass it via `WithCache()`.

3. **Load balancing:** Round-robin across instances. No sticky sessions required.

```go
// Example: Redis-backed cache
engine, _ := authly.New(cfg, authly.WithCache(myRedisCache))
```

### Caveat: JWKS Cache Stampede

If all instances start simultaneously and the JWKS cache expires at the same time, they all hit the JWKS endpoint simultaneously. Mitigations:

- Use `AllowStaleJWKS: true` — only one goroutine needs to succeed.
- Stagger instance starts slightly.
- Use a shared cache with a pre-warmed JWKS entry.

---

## Why No Background Goroutines for Refresh

goAuthly does not spawn background goroutines to refresh JWKS or introspection caches. This is a deliberate choice:

1. **Simplicity.** No goroutine lifecycle management, no shutdown coordination, no leak risk.
2. **Predictability.** Cache refresh happens on the request path. You know exactly when network calls happen.
3. **Control.** You decide when and how to refresh — not the library.

### How to Add Your Own Refresh Loop

If you want proactive JWKS refresh (to avoid cold-cache latency on the first request after TTL expiry):

```go
func refreshLoop(ctx context.Context, engine *authly.Engine, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            // Make a dummy verification to trigger JWKS refresh
            // Use a clearly invalid token so it fails fast after key fetch
            _, _ = engine.Verify(ctx, "refresh-trigger.invalid.token")
        }
    }
}

// Start it:
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
go refreshLoop(ctx, engine, 10*time.Minute)
```

This is a simple pattern that works. The invalid token fails verification quickly, but the JWKS fetch (triggered by the key lookup) refreshes the cache.

---

## Allocation Avoidance

- Token type detection: zero allocations (byte counting).
- Algorithm allowlist: precomputed at construction time.
- Cache key computation: single SHA-256 + string concatenation.
- Result construction: single allocation per verification.

## Concurrency

- The default cache (ristretto) is safe for concurrent use.
- The default HTTP client is safe for concurrent use.
- `Engine` is read-only after construction — safe to share across goroutines.
- `Result` is immutable once returned — safe to pass between goroutines.
