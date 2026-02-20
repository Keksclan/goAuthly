# JWT Validation Performance Optimizations

## What Changed

### 1. Precomputed Parser Options
`jwt.ParserOption` slice (leeway, expiration required, valid methods) is now built
once in `New()` and reused across every `Validate()` call. Previously a new slice
was allocated per request.

### 2. Precomputed Audience Rule Sets
The effective audience rule (legacy `Audience` string → `AudienceRule`) is resolved
at construction time. Blocklist, AnyOf, and AllOf values are stored in
`map[string]struct{}` sets for O(1) lookup instead of being rebuilt per call.

### 3. Single `time.Now()` Per Validation
All post-parse time checks (iat-in-future) share a single `now` capture, removing
redundant syscalls on the hot path.

### 4. JWKS Key Index (O(1) Lookup)
`IndexedKeyProvider` wraps any `jwk.Provider` with an `atomic.Pointer`-based
`map[kid]key` index. On JWKS refresh the index is rebuilt and swapped atomically.
Lookups are lock-free.

### 5. Fast-Fail Ordering
Validation rejects in cheapest-first order:
1. Algorithm allowed (parser + keyfunc defense-in-depth)
2. `kid` presence (when JWKS enabled)
3. Signature verification (via `jwt.Parse`)
4. Issuer exact match
5. `iat` not in future
6. Audience allow/block

### 6. Metrics Collector Interface
Optional `MetricsCollector` callback classifies every validation outcome
(ok / fail with reason bucket) with zero overhead when nil.

## Benchmark Command

```bash
go test -bench BenchmarkJWT -benchmem -count=5 ./tests/
```

## Benchmark Results

Run on: `11th Gen Intel Core i7-11850H @ 2.50GHz`, Windows, Go 1.24, `amd64`.

Command:
```bash
go test -bench "BenchmarkJWT|BenchmarkJWKS|BenchmarkValidate_" -benchmem -count=3 ./tests/
```

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| `BenchmarkJWTValidate_Valid` | ~66,000 | 4472 | 75 | Full valid-token path |
| `BenchmarkJWTValidate_InvalidAudience` | ~65,000 | 4360 | 69 | Fast reject after sig (fewer allocs) |
| `BenchmarkJWTValidate_InvalidIssuer` | ~58,000 | 4208 | 66 | Fast reject after sig |
| `BenchmarkJWTValidate_Expired` | ~58,000 | 4304 | 71 | Rejected by parser (no claims extraction) |
| `BenchmarkJWKSKeySelection` | ~16 | 0 | 0 | O(1) map lookup, zero allocs |
| `BenchmarkValidate_Standard` | ~61,000 | 4536 | 75 | Standard mode |
| `BenchmarkValidate_Throughput` | ~60,000 | 4536 | 75 | Throughput mode (pooling) |

Key observations:
- **JWKS key selection is O(1)** with zero allocations (~16 ns).
- **Invalid tokens are rejected faster** than valid ones (fewer allocations on early exit).
- **Parser options are precomputed** — no per-request slice allocation.
- **Audience sets are precomputed** — no per-request map construction.
- The RSA signature verification dominates (~55 µs), so structural optimizations
  improve the non-crypto overhead proportion significantly.
