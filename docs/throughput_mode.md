# High-Throughput Validator Mode

## What It Does

Throughput mode is an **opt-in** configuration that reduces per-request memory
allocations during JWT validation by using object pooling (`sync.Pool`) for
internal `Claims` structures. All other optimizations (precomputed parser
options, audience sets, atomic JWKS index) apply in both modes.

## How to Enable

```go
cfg := authly.Config{
    OAuth2: authly.OAuth2Config{
        // ... your existing settings ...
        HighThroughput: true,
    },
}
engine, err := authly.New(cfg)
```

Or at the validator level directly:

```go
v, err := jwt.New(jwt.Config{
    // ...
    Mode: jwt.ValidatorModeThroughput,
}, keyProvider)
```

## When to Use It

- **High QPS services** (>10 k req/s) where GC pressure from per-request
  `Claims` allocations is measurable.
- Services that validate the **same set of token shapes** repeatedly (e.g.
  machine-to-machine tokens with stable claims).

**Do not use** if your service processes fewer than a few thousand requests per
second — the default (standard) mode is already efficient.

## What Is Pooled

| Object | Why | Reset policy |
|--------|-----|--------------|
| `validationResult` (wraps `Claims`) | Avoids one heap allocation per validation | All fields zeroed before reuse; no sensitive data retained |

The pool is a standard `sync.Pool` — objects may be collected by the GC at any
time. No sensitive data (tokens, keys) is stored in the pool.

## Trade-offs

| Aspect | Standard | Throughput |
|--------|----------|------------|
| Allocations per call | Baseline | ~1 fewer heap alloc |
| GC pressure under load | Normal | Lower |
| Correctness | ✅ Identical | ✅ Identical |
| Security checks | ✅ Full | ✅ Full |
| Thread safety | ✅ | ✅ (pool is goroutine-safe) |

## Security Guarantee

**All security checks remain identical in both modes:**

- Allowed algorithms enforced at parser + keyfunc level
- `kid` required when JWKS is enabled
- Issuer exact match
- Audience allow + block (block wins)
- `exp` / `nbf` / `iat` + clock skew
- Signature verification always performed

The mode only affects memory management, never validation logic.

## Observability

An optional `MetricsCollector` interface can be provided to receive validation
outcome counters without adding external dependencies:

```go
type MetricsCollector interface {
    ValidationOK()
    ValidationFailed(reason string)
}
```

Failure reasons: `alg`, `kid`, `iss`, `aud`, `exp`, `nbf`, `iat`, `signature`, `parse`.

The collector must be safe for concurrent use and **must not** log tokens or claims.

## Benchmarks

```bash
go test -bench "BenchmarkValidate_(Standard|Throughput)" -benchmem -count=5 ./tests/
```

See `docs/perf.md` for full benchmark results.
