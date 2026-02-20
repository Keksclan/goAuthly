# Advanced Claims

goAuthly's claim system goes beyond simple "is this field present?" checks. It supports declarative policies, Lua scripting, conditional enforcement, cross-claim dependencies, token-type-aware validation, and actor claim handling.

---

## Declarative Claim Policy

The `ClaimPolicy` struct gives you four layers of control:

### Required Claims

Claims that **must** be present. Missing any one rejects the token.

```go
ClaimPolicy{
    Required: []string{"sub", "iss", "exp"},
}
```

### Denylist

Claims that **must NOT** be present. If any denied claim exists, the token is rejected. Useful for blocking sensitive data from leaking through tokens.

```go
ClaimPolicy{
    Denylist: []string{"password", "ssn", "credit_card"},
}
```

### Allowlist

When non-empty, **only** listed claims are permitted. Any unexpected claim triggers rejection. This is the strictest mode.

```go
ClaimPolicy{
    Allowlist: []string{"sub", "iss", "exp", "aud", "scope", "client_id"},
}
```

### Enforced Values

Constrains specific claim values. The claim must exist AND have one of the allowed values.

```go
ClaimPolicy{
    EnforcedValues: map[string][]any{
        "iss":    {"https://auth.example.com"},
        "aud":    {"my-api", "my-api-v2"},
        "scope":  {"read", "write"},
    },
}
```

Enforced values support these types: `string`, `bool`, `int`, `int32`, `int64`, `float32`, `float64`, `[]string`, and `[]any` (array of strings with any-match semantics).

### Combined Example

```go
ClaimPolicy{
    Required:  []string{"sub", "iss"},
    Denylist:  []string{"password"},
    Allowlist: []string{"sub", "iss", "exp", "aud", "scope"},
    EnforcedValues: map[string][]any{
        "iss": {"https://auth.example.com"},
    },
}
```

Evaluation order: Required → Denylist → Allowlist → EnforcedValues.

---

## Lua Policy

Lua scripts run **after** declarative policies. They enable conditional logic that declarative rules can't express.

### Available Functions

| Function | Description |
|----------|-------------|
| `has(key)` | Returns `true` if the claim exists |
| `get(key)` | Returns the claim value (string, number, bool, or nil) |
| `require_claim(key)` | Rejects the token if the claim is missing |
| `require_value(key, value)` | Rejects if the claim doesn't match the value |
| `require_one_of(key, {values})` | Rejects if the claim isn't one of the values |
| `reject(message)` | Immediately rejects with a custom message |
| `token_type()` | Returns `"jwt"`, `"opaque"`, or `"basic"` |
| `is_jwt()` | Returns `true` if the token is a JWT |
| `is_opaque()` | Returns `true` if the token is opaque |

### Basic Example

```lua
-- Require "sub" claim on all tokens
require_claim("sub")

-- Enforce issuer
require_value("iss", "https://auth.example.com")
```

### Conditional Enforcement

Apply different rules based on which claims are present:

```lua
if has("actor") then
    -- Delegated tokens must have a specific issuer
    require_value("iss", "https://auth.example.com")
    require_claim("sub")
end

if has("client_id") and not has("sub") then
    -- Client credentials flow: require scope
    require_claim("scope")
    require_one_of("scope", {"read", "write", "admin"})
end
```

### Cross-Claim Dependency

Enforce that certain claims must appear together:

```lua
-- If "department" is present, "role" must also be present
if has("department") then
    require_claim("role")
end

-- If "admin" scope is present, require MFA claim
if has("scope") then
    local scope = get("scope")
    if scope == "admin" then
        require_claim("mfa_verified")
        require_value("mfa_verified", true)
    end
end
```

### Token-Type-Aware Validation

Different token types often carry different claims:

```lua
if is_jwt() then
    require_claim("exp")
    require_claim("iat")
    require_value("iss", "https://auth.example.com")
end

if is_opaque() then
    require_claim("client_id")
    require_claim("scope")
end

if token_type() == "basic" then
    -- Basic auth results have minimal claims
    require_claim("sub")
end
```

### Rejection with Custom Messages

```lua
if has("banned") then
    reject("account has been banned")
end

if not has("email_verified") then
    reject("email verification required")
end
```

### Complex Real-World Example

```lua
-- Service-to-service tokens (no sub, has client_id)
if has("client_id") and not has("sub") then
    require_one_of("client_id", {
        "billing-service",
        "notification-service",
        "analytics-service"
    })
    require_claim("scope")
end

-- User tokens (has sub)
if has("sub") then
    require_claim("iss")
    require_value("iss", "https://auth.example.com")

    -- Admin endpoints require elevated scope
    if has("scope") then
        local scope = get("scope")
        if scope == "admin" then
            require_claim("mfa_verified")
        end
    end
end

-- Delegated tokens (has actor)
if has("actor") then
    require_claim("sub")
    -- Only specific services can delegate
    require_one_of("azp", {
        "delegation-gateway",
        "api-proxy"
    })
end
```

---

## Actor Claim Handling

RFC 8693 defines the `act` (actor) claim for token exchange scenarios where one party acts on behalf of another.

### Configuration

```go
Policies: authly.Policies{
    Actor: authly.ActorPolicy{
        Enabled:              true,
        ActorClaimKey:        "act",                    // claim key to look for
        ActorSubjectKey:      "sub",                    // key within the actor object
        AllowedActorSubjects: []string{"service-a", "proxy-b"},
    },
}
```

### Actor Claim Formats

goAuthly supports two formats:

**Object format** (RFC 8693 standard):
```json
{
    "sub": "user@example.com",
    "act": {
        "sub": "service-a"
    }
}
```

**String format** (simplified):
```json
{
    "sub": "user@example.com",
    "act": "service-a"
}
```

### Actor Claim Sub-Policy

You can apply a separate `ClaimPolicy` to the actor's claims:

```go
Actor: authly.ActorPolicy{
    Enabled:       true,
    ActorClaimKey:  "act",
    ActorSubjectKey: "sub",
    AllowedActorSubjects: []string{"service-a"},
    ActorClaimsPolicy: &authly.ClaimPolicy{
        Required: []string{"sub"},
        Denylist: []string{"admin"},
    },
},
```

### Result

When an actor is present and validated, it's available in the `Result`:

```go
result, _ := engine.Verify(ctx, token)
if result.Actor != nil {
    fmt.Printf("Acting as: %s\n", result.Actor.Subject)
    fmt.Printf("Actor claims: %v\n", result.Actor.Claims)
}
```

### Edge Cases

| Scenario | Behavior |
|----------|----------|
| Actor policy enabled, claim missing | `ErrActorMissing` |
| Actor policy disabled, claim present | Ignored (no validation) |
| Actor subject not in allowed list | `ErrActorNotAllowed` |
| Actor claim is neither string nor object | `ErrActorMissing` (unexpected type) |
| Actor object missing `sub` key | `ErrActorMissing` |

---

## Type-Specific Policies

You can set different claim policies for JWT and opaque tokens:

```go
Policies: authly.Policies{
    // Shared fallback (backward compatible)
    TokenClaims: authly.ClaimPolicy{
        Required: []string{"sub"},
    },

    // JWT-specific (overrides TokenClaims for JWTs)
    JWTClaims: authly.ClaimPolicy{
        Required: []string{"sub", "exp", "iat"},
        EnforcedValues: map[string][]any{
            "iss": {"https://auth.example.com"},
        },
    },

    // Opaque-specific (overrides TokenClaims for opaque tokens)
    OpaqueClaims: authly.ClaimPolicy{
        Required: []string{"sub", "client_id"},
    },
}
```

**Resolution order:**
1. If `JWTClaims`/`OpaqueClaims` is non-empty → use it.
2. Else if `TokenClaims` is non-empty → use it as fallback.
3. Else → no claim policy (permit all).

Basic Auth always uses `TokenClaims` (there are no `BasicClaims`).

## ApplyTo Filter

A `ClaimPolicy` can be restricted to specific token types:

```go
ClaimPolicy{
    Required: []string{"client_id"},
    ApplyTo:  []authly.TokenType{authly.TokenTypeOpaque},
}
```

This policy only runs for opaque tokens. JWT and basic auth tokens skip it entirely.
