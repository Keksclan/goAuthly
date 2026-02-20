# High-Throughput Validator Mode

## What It Does

Throughput mode is an **opt-in** configuration that enables precomputed
structures and fast-path optimizations for JWT validation. All optimizations
(precomputed parser options, audience sets, atomic JWKS index) apply in both
modes; throughput mode signals intent for high-QPS workloads.

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

- **High QPS services** (>10 k req/s) where you want to ensure all available
  optimizations are active.
- Services that validate the **same set of token shapes** repeatedly (e.g.
  machine-to-machine tokens with stable claims).

**Do not use** if your service processes fewer than a few thousand requests per
second — the default (standard) mode is already efficient.

## Trade-offs

| Aspect | Standard | Throughput |
|--------|----------|------------|
| Allocations per call | Baseline | Identical |
| Correctness | ✅ Identical | ✅ Identical |
| Security checks | ✅ Full | ✅ Full |
| Thread safety | ✅ | ✅ |

## Security Guarantee

**All security checks remain identical in both modes:**

- Allowed algorithms enforced at parser + keyfunc level
- `kid` required when JWKS is enabled
- Issuer exact match
- Audience allow + block (block wins)
- `exp` / `nbf` / `iat` + clock skew
- Signature verification always performed

The mode only affects configuration intent, never validation logic.

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
