# Performance Notes

This document explains the main hot paths and the caching strategies used by goAuthly.

## Hot Paths

- Token type detection: O(1) check using a `.` count to route to JWT or opaque flow without allocations.
- JWT validation: uses `github.com/golang-jwt/jwt/v5`. We avoid per-request linear scans by precomputing a set of allowed algorithms.
- Opaque validation: caches introspection responses with a short TTL to reduce round-trips under load.

## Caching Strategy

### JWKS Caching

- JWKS are fetched via the JWK Manager and cached under a fresh key with the configured TTL.
- Optionally, a stale copy is kept longer (4x TTL, minimum 1h) and may be used if refresh fails, improving resilience.
- Keys are extracted and reused from the parsed set; only RSA/ECDSA public keys are accepted.

### Introspection Caching

- Only active responses are cached to avoid persisting negative or ambiguous states.
- Cache keys do not include the raw opaque token: a SHA-256 hash of the token plus endpoint identity is used instead.
- Short TTLs (e.g., 10–60s) help balance correctness and load reduction.

## Allocation Avoidance

- Token type pre-check avoids parsing for the wrong flow.
- String splitting is avoided; we only count `.` for JWT detection.
- Reusable structures (e.g., algorithm allow-set) are created at construction time.

## Security Considerations

- Never store raw opaque tokens as cache keys; they are treated as secrets.
- Validate issuer, audience, and algorithm choices explicitly.

## Concurrency

- The default cache (ristretto) and HTTP clients are safe for concurrent use.
- `Engine` is read-only after construction and safe to share across goroutines.
