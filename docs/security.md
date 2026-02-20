# Security

goAuthly is a verification library. It doesn't issue tokens, manage sessions, or store credentials. But verification is the front door to your service, so getting it wrong is expensive. This document covers the security model, threat mitigations, and recommended production configuration.

---

## Why Raw Tokens Aren't Cached

Caching introspection responses is important for performance, but the cache key matters. If you use the raw opaque token as a cache key, anyone with access to the cache (memory dump, debug endpoint, logging accident) gets a valid token.

goAuthly hashes the token with SHA-256 before using it as a cache key:

```go
key = "introspect:" + sha256(token) + ":" + endpoint
```

The token itself is never stored in the cache. The cached value is the introspection response (active/inactive, claims, etc.).

## Why Opaque Tokens Are Hashed for Cache Keys

Even in-memory caches can leak:
- Memory dumps during crash analysis
- Debug endpoints that enumerate cache keys
- Side-channel attacks in shared hosting

SHA-256 hashing ensures that even if the cache is exposed, the original tokens cannot be recovered.

## Why No Panics Are Allowed

A panic in a Go HTTP handler (or gRPC interceptor) kills the goroutine or, worse, the entire process. In an auth library, this creates two problems:

1. **Denial of service**: A crafted input that triggers a panic becomes a DoS vector.
2. **Security bypass**: If recovery middleware catches the panic but continues processing, the request may proceed unauthenticated.

goAuthly enforces a strict no-panic rule:
- All type assertions use the comma-ok pattern: `v, ok := x.(Type)`
- All map accesses are guarded.
- Third-party library boundaries are wrapped in error handling.
- The `tests/no_panic_test.go` suite fuzzes the engine with malformed inputs.

## Timing Attack Mitigation

### JWT Verification

JWT signature verification is performed by the underlying crypto libraries (`crypto/rsa`, `crypto/ecdsa`), which use constant-time operations.

### Opaque Token Introspection

Introspection delegates to an external endpoint. The timing of the response depends on the introspection server, not goAuthly. Cached responses return in constant time.

### Basic Auth

Basic Auth is the most timing-sensitive path. goAuthly mitigates timing attacks at two levels:

1. **bcrypt comparison**: `bcrypt.CompareHashAndPassword` takes the same time regardless of which byte differs.
2. **User enumeration protection**: When the username doesn't exist, a dummy bcrypt comparison is performed so the response time is the same as for a valid username with a wrong password.

```go
// From internal/basic/basic.go
if !exists {
    _ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
    return ErrInvalidCredentials
}
```

## Claim Enforcement Philosophy

goAuthly takes a **deny-by-default** approach when allowlists are configured:

- If `Allowlist` is non-empty, any claim NOT in the list is rejected.
- `Required` claims must be present.
- `Denylist` claims must be absent.
- `EnforcedValues` constrains specific claim values.

This layered approach lets you express security constraints declaratively:

```go
ClaimPolicy{
    Required:  []string{"sub", "iss"},       // must exist
    Denylist:  []string{"admin", "password"}, // must NOT exist
    Allowlist: []string{"sub", "iss", "exp", "aud", "scope"}, // only these allowed
    EnforcedValues: map[string][]any{
        "iss": {"https://trusted-issuer.com"},
    },
}
```

## Actor Claim Abuse Scenarios

RFC 8693 actor claims (`act`) represent delegation: "User A is acting on behalf of User B." This is powerful but dangerous if not validated.

**Scenario 1: Actor impersonation**
An attacker forges a token with `act.sub = "admin"`. Without `AllowedActorSubjects`, any actor is accepted.

**Mitigation:** Always set `AllowedActorSubjects` when actor policy is enabled.

**Scenario 2: Missing actor validation**
A token has an `act` claim, but the server doesn't check it. The actor could be anyone.

**Mitigation:** Enable `ActorPolicy` and set `ActorClaimKey` to validate the actor.

**Scenario 3: Actor claim injection**
A malicious introspection server adds an unexpected `act` claim to the response.

**Mitigation:** Use `Denylist` or `Allowlist` to control which claims are accepted.

## JWKS Authentication Risks

JWKS endpoints are typically public, but some deployments require authentication. goAuthly supports Basic, Bearer, and custom header auth for JWKS fetches.

**Risk:** If JWKS auth credentials are weak or leaked, an attacker could serve malicious keys.

**Mitigations:**
- Use HTTPS for all JWKS URLs.
- Rotate JWKS auth credentials regularly.
- Set `AllowedAlgs` to restrict which algorithms are accepted.
- Enable `AllowStaleJWKS` to survive temporary JWKS unavailability without falling back to unverified keys.

## Introspection: Header vs Body Differences

RFC 7662 specifies sending the token in the POST body. Some servers accept it in a header instead.

| Transport | Config | Security Note |
|-----------|--------|---------------|
| Body (default) | `TokenTransportBody` | Standard RFC 7662. Token in POST body. |
| Header | `TokenTransportHeader` | Token in a request header (e.g., `Authorization: Bearer <token>`). May be logged by proxies. |

**Recommendation:** Use body transport unless your introspection server requires header transport. Tokens in headers are more likely to appear in access logs.

## Recommended Production Config

```go
cfg := authly.Config{
    Mode: authly.AuthModeOAuth2,
    OAuth2: authly.OAuth2Config{
        Mode:        authly.OAuth2JWTAndOpaque,
        Issuer:      "https://your-issuer.com",        // always set
        Audience:    "your-api",                        // always set
        AllowedAlgs: []string{"RS256", "ES256"},        // always restrict
        JWKSURL:     "https://your-issuer.com/.well-known/jwks.json",
        JWKSCacheTTL:   15 * time.Minute,
        AllowStaleJWKS: true,                           // resilience
        Introspection: authly.IntrospectionConfig{
            Endpoint: "https://your-issuer.com/introspect",
            Timeout:  5 * time.Second,
            Auth: authly.ClientAuth{
                Kind:         authly.ClientAuthBasic,
                ClientID:     "your-client-id",
                ClientSecret: "your-client-secret",     // from env/vault
            },
        },
        IntrospectionCacheTTL: 30 * time.Second,
        Opaque: authly.OpaquePolicy{
            RequireActive:     true,                    // default
            ExposeActiveClaim: false,                   // don't leak to Result
        },
    },
    Policies: authly.Policies{
        TokenClaims: authly.ClaimPolicy{
            Required: []string{"sub"},
            Denylist: []string{"password"},
        },
    },
}
```

### Audience Blocklist

Even with `AnyAudience: true`, the **blocklist always wins**. Use it to deny
specific audiences that should never be accepted — for example, internal service
audiences that external tokens must not carry:

```go
AudienceRule: authly.AudienceRule{
    AnyAudience: true,
    Blocklist:   []string{"internal-admin", "system-cron"},
}
```

Blocklist is checked first, before any allow logic runs. This is by design:
deny rules must not be bypassed by permissive allow rules.

### Required Metadata as a Security Layer

Required metadata headers act as an additional gate. If your API gateway
is supposed to inject `X-User-Sub` after its own verification, requiring that
header in goAuthly adapters ensures a misconfigured gateway doesn't silently
let requests through without it.

This is **defense in depth**, not a replacement for token verification.

### Checklist
- [ ] `Issuer` and `Audience` (or `AudienceRule`) are set and match your identity provider.
- [ ] `AudienceRule.Blocklist` denies any audiences that should never be accepted.
- [ ] `AllowedAlgs` is restricted to algorithms you actually use.
- [ ] JWKS URL uses HTTPS.
- [ ] Introspection endpoint uses HTTPS.
- [ ] Client credentials come from environment variables or a vault, not hardcoded.
- [ ] `RequireActive` is `true` for opaque tokens.
- [ ] Claim policies reject unexpected claims.
- [ ] Basic Auth passwords are bcrypt hashes, never plaintext.
- [ ] Actor policy (if used) has `AllowedActorSubjects` set.
- [ ] Required metadata headers are configured when upstream gateway headers are expected.
- [ ] No `panic()` calls in your own middleware wrapping goAuthly.
