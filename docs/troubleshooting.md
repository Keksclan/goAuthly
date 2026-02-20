# Troubleshooting

<p align="center"><img src="../img.png" alt="Schnallbert" width="128" /><br/><em>Schnallbert says: "Something broke? Let's fix it together!"</em></p>

When auth doesn't work, the error messages can feel cryptic. This guide covers the most common issues, what causes them, and how to fix them — without adding a logging framework to your binary.

---

## "Token rejected but looks valid"

**Symptoms:** You decode the JWT on jwt.io and it looks fine, but goAuthly rejects it.

**Common causes:**

1. **Issuer mismatch.** The token's `iss` claim doesn't match `Config.OAuth2.Issuer`. Even a trailing slash matters: `https://auth.example.com` ≠ `https://auth.example.com/`.

2. **Audience mismatch.** The token's `aud` claim doesn't include `Config.OAuth2.Audience`. Note: `aud` can be a string or an array — goAuthly handles both, but your IdP might set a different audience than you expect.

3. **Algorithm not allowed.** If `AllowedAlgs` is set and the token uses an algorithm not in the list, it's rejected. Check the token's `alg` header.

4. **Clock skew.** The token's `exp` is in the past or `nbf` is in the future. Check your server's clock: `date -u` (Linux) or `Get-Date -Format o` (PowerShell).

5. **Wrong key.** The JWKS might have rotated keys. If `AllowStaleJWKS` is false and the cache is stale, the old key might not match.

**Debug steps:**

```go
// Decode the JWT header without verification to see what it expects
parts := strings.SplitN(token, ".", 3)
header, _ := base64.RawURLEncoding.DecodeString(parts[0])
fmt.Println("JWT Header:", string(header))
// Check: alg, kid, typ

// Compare with your config
fmt.Println("Allowed algs:", cfg.OAuth2.AllowedAlgs)
fmt.Println("Expected issuer:", cfg.OAuth2.Issuer)
fmt.Println("Expected audience:", cfg.OAuth2.Audience)
```

---

## "JWKS not refreshing"

**Symptoms:** New keys from your IdP aren't picked up. Tokens signed with new keys are rejected.

**Common causes:**

1. **Cache TTL too long.** The default `JWKSCacheTTL` is 15 minutes. If your IdP rotated keys more recently, the old keys are still cached.

2. **Stale JWKS fallback.** If `AllowStaleJWKS` is true and the refresh fails (network error, IdP down), goAuthly serves stale keys. This is resilient but means new keys won't appear until a successful refresh.

3. **HTTP client timeout.** The default HTTP client has a 10-second timeout. If your JWKS endpoint is slow, the fetch might time out silently.

**Debug steps:**

```go
// Reduce cache TTL temporarily
cfg.OAuth2.JWKSCacheTTL = 30 * time.Second

// Or force a shorter HTTP timeout
engine, _ := authly.New(cfg, authly.WithHTTPClient(&http.Client{
    Timeout: 5 * time.Second,
}))

// Verify JWKS endpoint is reachable
resp, err := http.Get(cfg.OAuth2.JWKSURL)
fmt.Println("Status:", resp.StatusCode, "Error:", err)
```

---

## "Introspection returns active but still rejected"

**Symptoms:** Your introspection endpoint returns `{"active": true, ...}` but goAuthly still rejects the token.

**Common causes:**

1. **Claim policy rejection.** The introspection response becomes the claims map. If your `ClaimPolicy` requires `sub` but the introspection response doesn't include it — rejected.

2. **Lua policy rejection.** Your Lua script might reject based on a claim present in the introspection response.

3. **Actor policy rejection.** If actor policy is enabled and the introspection response contains (or doesn't contain) an actor claim.

4. **Denylist hit.** The introspection response might include a claim in your denylist.

**Debug steps:**

```go
// Temporarily remove all policies to isolate the issue
cfg.Policies = authly.Policies{}
engine, _ := authly.New(cfg)
result, err := engine.Verify(ctx, token)
fmt.Println("Without policies:", result, err)

// Then add policies back one at a time:
// 1. TokenClaims only
// 2. + Lua
// 3. + Actor
```

---

## "Basic auth works locally but not in production"

**Symptoms:** `VerifyBasic` succeeds in dev but fails in production with `ErrInvalidCredentials`.

**Common causes:**

1. **Plaintext passwords in dev, hashes in production (or vice versa).** The `Users` map must always contain bcrypt hashes. If you accidentally used plaintext locally, it seemed to "work" because bcrypt comparison of a plaintext string against a plaintext "hash" might not behave as expected.

2. **Different bcrypt cost.** If you generated hashes with `bcrypt.MinCost` in dev and `bcrypt.DefaultCost` in production, the hashes are different (but should still verify correctly — this usually isn't the issue).

3. **Password encoding.** Ensure passwords are UTF-8. If there's a character encoding mismatch between what the client sends and what was hashed, comparison fails.

4. **Adapter not parsing Basic header correctly.** Ensure the client sends `Authorization: Basic <base64(user:pass)>` with proper base64 encoding. The colon separating username and password is mandatory.

**Debug steps:**

```go
import "golang.org/x/crypto/bcrypt"

// Verify the hash matches the password
hash := cfg.BasicAuth.Users["admin"]
err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("the-password"))
fmt.Println("Hash valid:", err == nil)

// Generate a fresh hash for comparison
fresh, _ := bcrypt.GenerateFromPassword([]byte("the-password"), bcrypt.DefaultCost)
fmt.Println("Fresh hash:", string(fresh))
```

---

## "unsupported auth mode"

**Causes:**

1. `Config.Mode` is empty. Default is `AuthModeOAuth2`, but if set to an empty string after defaulting is bypassed, this triggers.
2. Calling `engine.Verify()` when `Mode` is `AuthModeBasic`. Use `engine.VerifyBasic()` instead.
3. Calling `engine.VerifyBasic()` when `BasicAuth.Enabled` is false or not configured.

---

## "basic auth requires Users map or Validator function"

You set `Mode: AuthModeBasic` and `BasicAuth.Enabled: true` but didn't provide either `Users` or `Validator`. At least one credential source is required.

---

## General Debug Strategy

goAuthly intentionally doesn't include a logging framework. Here's how to debug without one:

### 1. Wrap the Engine

```go
func debugVerify(engine *authly.Engine, ctx context.Context, token string) (*authly.Result, error) {
    result, err := engine.Verify(ctx, token)
    if err != nil {
        fmt.Printf("[AUTH DEBUG] Verify failed: %v\n", err)
        fmt.Printf("[AUTH DEBUG] Token (first 20 chars): %.20s...\n", token)
        return nil, err
    }
    fmt.Printf("[AUTH DEBUG] OK: type=%s sub=%s\n", result.Type, result.Subject)
    return result, nil
}
```

### 2. Check the Error Chain

goAuthly uses wrapped errors. Unwrap to find the root cause:

```go
result, err := engine.Verify(ctx, token)
if err != nil {
    fmt.Println("Error:", err)

    // Check specific error types
    if errors.Is(err, authly.ErrClaimMissing) {
        fmt.Println("A required claim is missing")
    }
    if errors.Is(err, authly.ErrClaimForbidden) {
        fmt.Println("A denied claim was found")
    }
    if errors.Is(err, authly.ErrLuaPolicy) {
        fmt.Println("Lua policy rejected the token")
    }
}
```

### 3. Test in Isolation

```go
// Test claim policy separately
policy := cfg.Policies.TokenClaims
claims := map[string]any{"sub": "user", "iss": "https://issuer.com"}
err := policy.Validate(claims)
fmt.Println("Policy result:", err)
```

### 4. Verify External Dependencies

```go
// Test JWKS endpoint
resp, _ := http.Get(cfg.OAuth2.JWKSURL)
body, _ := io.ReadAll(resp.Body)
fmt.Println("JWKS:", string(body))

// Test introspection endpoint
// (use curl or a test HTTP client)
```

---

## Error Reference

| Error | Sentinel | Meaning |
|-------|----------|---------|
| `unsupported auth mode` | `ErrUnsupportedMode` | Wrong mode or method for the configured mode |
| `invalid token` | `ErrInvalidToken` | Token format doesn't match configured mode |
| `required claim missing: X` | `ErrClaimMissing` | Claim X is required but absent |
| `claim is forbidden: X` | `ErrClaimForbidden` | Claim X is in the denylist |
| `claim value not allowed: X` | `ErrClaimValueNotAllowed` | Claim X has an unexpected value |
| `unknown claim not allowed: X` | `ErrUnknownClaimNotAllowed` | Claim X is not in the allowlist |
| `actor claim missing` | `ErrActorMissing` | Actor policy enabled but actor claim absent |
| `actor subject not allowed` | `ErrActorNotAllowed` | Actor subject not in allowed list |
| `lua policy violation` | `ErrLuaPolicy` | Lua script rejected the token |
| `basic auth failed` | `ErrBasicAuthFailed` | Basic auth credentials invalid |
| `invalid credentials` | `basic.ErrInvalidCredentials` | Username/password mismatch |
| `audience blocked: X` | `ErrAudienceBlocked` | Token audience X is in the blocklist |
| `audience not allowed: ...` | `ErrAudienceNotAllowed` | Token audience doesn't satisfy AnyOf/AllOf rules |
| `audience missing` | `ErrAudienceMissing` | Token has no audience claim (when required) |
| `missing required metadata: X` | `ErrMissingRequiredMetadata` | Required header/metadata X is missing or empty |

---

## Audience Rule Troubleshooting

**"audience blocked" but I expected it to pass?**
Blocklist always wins — even with `AnyAudience: true`. Check your `Blocklist` entries.

**"audience not allowed" with AnyOf?**
The token must contain *at least one* of the `AnyOf` values. Check `aud` claim in your token (it can be a string or array).

**"audience not allowed" with AllOf?**
The token must contain *all* of the `AllOf` values. A missing single value causes rejection.

**Legacy `Audience` string still working?**
Yes. If `AudienceRule` is zero-valued, the old `Audience` string is auto-converted. Set `AudienceRule` explicitly to override.

## Required Metadata Troubleshooting

**"missing required metadata: X-User-Sub" on every request?**
Your client/gateway isn't sending the header. For gRPC, remember keys must be lower-case (`x-user-sub`, not `X-User-Sub`).

**Metadata validation blocks even with a valid token?**
Correct — metadata is checked *before* token verification. Fix the missing header first.
