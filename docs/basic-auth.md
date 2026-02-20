# Basic Authentication

<p align="center"><img src="../img.png" alt="Schnallbert" width="128" /><br/><em>Schnallbert says: "bcrypt or bust — no plaintext on my watch!"</em></p>

goAuthly supports HTTP Basic Authentication as a first-class verification mode. It's intentionally minimal — just enough to be secure, not enough to become a user management system.

---

## Why Hashed Passwords Are Required

Storing plaintext passwords is never acceptable, not even "temporarily" or "for testing." The `Users` map requires **bcrypt hashes**, not raw strings.

```go
import "golang.org/x/crypto/bcrypt"

hash, err := bcrypt.GenerateFromPassword([]byte("my-password"), bcrypt.DefaultCost)
// hash looks like: $2a$10$N9qo8uLOickgx2ZMRZoMye...
```

**Why bcrypt specifically?**
- It's deliberately slow, making brute-force attacks expensive.
- It includes a built-in salt, so identical passwords produce different hashes.
- It's the industry standard minimum for password storage.

If you need argon2, scrypt, or another algorithm — use the custom `Validator` function instead.

## Why Constant-Time Comparison Matters

When comparing passwords naively (byte-by-byte, short-circuiting on first mismatch), an attacker can measure response time to determine how many characters of the password are correct. This is a **timing attack**.

goAuthly mitigates this in two ways:

1. **bcrypt.CompareHashAndPassword** is inherently constant-time for a given cost factor.
2. **Unknown usernames** trigger a dummy bcrypt comparison to prevent user enumeration — the response time is the same whether the user exists or not.

## Configuration

### Static Users Map

```go
cfg := authly.Config{
    Mode: authly.AuthModeBasic,
    BasicAuth: authly.BasicAuthConfig{
        Enabled: true,
        Users: map[string]string{
            "admin":   "$2a$10$...",  // bcrypt hash
            "service": "$2a$10$...",  // bcrypt hash
        },
        Realm: "MyAPI",
    },
}
engine, err := authly.New(cfg)
result, err := engine.VerifyBasic(ctx, "admin", "password")
```

### Custom Validator (Database Lookup)

For dynamic credentials (database, LDAP, external service), use the `Validator` function:

```go
cfg := authly.Config{
    Mode: authly.AuthModeBasic,
    BasicAuth: authly.BasicAuthConfig{
        Enabled: true,
        Validator: func(ctx context.Context, username, password string) (bool, error) {
            user, err := db.FindUser(ctx, username)
            if err != nil {
                return false, err  // internal error — will be propagated
            }
            if user == nil {
                return false, nil  // user not found — returns ErrInvalidCredentials
            }
            return bcrypt.CompareHashAndPassword(
                []byte(user.PasswordHash), []byte(password),
            ) == nil, nil
        },
    },
}
```

**Important:** When `Validator` is set, it **always** takes priority over the `Users` map, even if both are configured. This is by design — it prevents accidental credential bypass.

### Realm

The `Realm` string is used in the `WWW-Authenticate` header returned by adapters:

```
WWW-Authenticate: Basic realm="MyAPI"
```

If not set, it defaults to `"Restricted"`.

## Result Shape

A successful `VerifyBasic` call returns:

```go
&authly.Result{
    Type:    "basic",
    Source:  "basic",
    Subject: "admin",  // the username
    Claims: map[string]any{
        "auth_method": "basic",
        "sub":         "admin",
    },
}
```

- `result.IsBasic()` returns `true`
- `result.IsJWT()` returns `false`
- `result.IsOpaque()` returns `false`

## Combining with OAuth2 (Mixed Deployments)

In many real-world systems, you need both token-based auth (for users/SPAs) and basic auth (for service accounts or legacy integrations).

### Option 1: OAuth2 Primary with Basic Auth Enabled

```go
cfg := authly.Config{
    Mode: authly.AuthModeOAuth2,
    OAuth2: authly.OAuth2Config{
        Mode:    authly.OAuth2JWTAndOpaque,
        JWKSURL: "https://auth.example.com/.well-known/jwks.json",
        Introspection: authly.IntrospectionConfig{
            Endpoint: "https://auth.example.com/introspect",
        },
    },
    BasicAuth: authly.BasicAuthConfig{
        Enabled: true,
        Users:   map[string]string{"svc-account": "$2a$10$..."},
    },
}
engine, _ := authly.New(cfg)

// In your adapter or handler, dispatch based on the Authorization header:
// - "Bearer ..." → engine.Verify(ctx, token)
// - "Basic ..."  → engine.VerifyBasic(ctx, user, pass)
```

The built-in adapters (gRPC, Fiber, fasthttp) handle this dispatching automatically.

### Option 2: Basic Auth Only

```go
cfg := authly.Config{
    Mode: authly.AuthModeBasic,
    BasicAuth: authly.BasicAuthConfig{
        Enabled: true,
        Users:   map[string]string{"admin": "$2a$10$..."},
    },
}
```

In this mode, `engine.Verify()` returns `ErrUnsupportedMode`. Only `engine.VerifyBasic()` works.

## Policies and Basic Auth

Basic Auth results go through the same policy pipeline as tokens:

1. **Declarative claim policy** (`Policies.TokenClaims`) — validates the claims map (`auth_method`, `sub`).
2. **Lua policy** — if enabled, receives the claims with `token_type() == "basic"`.

Actor policy is not applied to Basic Auth results (there's no actor claim).

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Empty username | Returns `ErrInvalidCredentials` |
| Empty password | Returns `ErrInvalidCredentials` (bcrypt comparison fails) |
| `Users` map is nil, `Validator` is nil | `New()` returns error |
| `Enabled: false` with `Mode: AuthModeBasic` | `New()` returns validation error |
| `Validator` returns `(false, someError)` | Error is wrapped and propagated |
| `Validator` returns `(true, nil)` | Credentials accepted |
| Password longer than 72 bytes | bcrypt silently truncates; use `Validator` for longer passwords |

> **bcrypt's 72-byte limit:** bcrypt only considers the first 72 bytes of a password. If your users might have passwords longer than that (unlikely but possible), use a custom `Validator` that pre-hashes with SHA-256 before bcrypt comparison.
