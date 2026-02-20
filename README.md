# goAuthly

> Think of goAuthly as a bouncer. It doesn't throw the party. It just decides who gets in.

Lightweight, focused token and credential verification for Go services. Supports OAuth2 JWT, opaque tokens (RFC 7662), and Basic Authentication — with declarative and Lua-based claim policies.

---

## What goAuthly Is

- A **verification-only** library — it validates tokens and credentials, nothing else.
- Supports **JWT** (via JWKS), **opaque tokens** (via introspection), and **Basic Auth** (bcrypt).
- Ships with thin adapters for **gRPC**, **Fiber**, and **fasthttp**.
- Offers declarative claim policies, Lua scripting, and actor validation (RFC 8693).
- Designed for production: no panics, constant-time comparisons, safe defaults.

## What goAuthly Is NOT

- It is **not** an identity provider, OAuth2 server, or session manager.
- It does **not** issue tokens, manage users, or handle login flows.
- It does **not** include a logging framework — bring your own.
- It does **not** store secrets; you provide hashed passwords and endpoints.

---

## Quick Start

```bash
go get github.com/keksclan/goAuthly
```

Run the end-to-end example locally:

```bash
go run ./examples/verify_demo
```

The example spins up a local HTTP server that serves a JWKS, implements introspection, mints a signed JWT, and demonstrates verifying both a JWT and an opaque token.

---

## JWT Example

```go
cfg := authly.Config{
    Mode: authly.AuthModeOAuth2,
    OAuth2: authly.OAuth2Config{
        Mode:     authly.OAuth2JWTOnly,
        Issuer:   "https://auth.example.com",
        Audience: "my-api",
        JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
    },
}
engine, err := authly.New(cfg)
if err != nil {
    log.Fatal(err)
}

result, err := engine.Verify(ctx, jwtToken)
if err != nil {
    // token is invalid
}
fmt.Println(result.Subject, result.Claims)
```

## Opaque Token Example

```go
cfg := authly.Config{
    Mode: authly.AuthModeOAuth2,
    OAuth2: authly.OAuth2Config{
        Mode: authly.OAuth2OpaqueOnly,
        Introspection: authly.IntrospectionConfig{
            Endpoint: "https://auth.example.com/introspect",
            Auth: authly.ClientAuth{
                Kind:         authly.ClientAuthBasic,
                ClientID:     "my-client",
                ClientSecret: "my-secret",
            },
        },
    },
}
engine, err := authly.New(cfg)
result, err := engine.Verify(ctx, opaqueToken)
```

## Basic Auth Example

```go
import "golang.org/x/crypto/bcrypt"

hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.DefaultCost)

cfg := authly.Config{
    Mode: authly.AuthModeBasic,
    BasicAuth: authly.BasicAuthConfig{
        Enabled: true,
        Users: map[string]string{
            "admin": string(hash),
        },
        Realm: "MyAPI",
    },
}
engine, err := authly.New(cfg)
result, err := engine.VerifyBasic(ctx, "admin", "s3cret")
// result.Type == "basic", result.Subject == "admin"
```

### Custom Validator (e.g., database lookup)

```go
cfg := authly.Config{
    Mode: authly.AuthModeBasic,
    BasicAuth: authly.BasicAuthConfig{
        Enabled: true,
        Validator: func(ctx context.Context, user, pass string) (bool, error) {
            return myDB.CheckCredentials(ctx, user, pass)
        },
    },
}
```

When both `Users` and `Validator` are provided, **Validator wins**.

## Mixed Mode Example

Use OAuth2 as the primary mode with Basic Auth also enabled:

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
        Users:   map[string]string{"svc-account": hashedPassword},
    },
}
engine, _ := authly.New(cfg)

// Use engine.Verify(ctx, token) for Bearer tokens
// Use engine.VerifyBasic(ctx, user, pass) for Basic Auth
```

## Claim Policy Example

```go
Policies: authly.Policies{
    TokenClaims: authly.ClaimPolicy{
        Required:       []string{"sub", "iss"},
        Denylist:       []string{"password", "ssn"},
        Allowlist:      []string{"sub", "iss", "exp", "aud", "scope"},
        EnforcedValues: map[string][]any{
            "iss": {"https://auth.example.com"},
        },
    },
}
```

Type-specific policies override the shared `TokenClaims`:

```go
Policies: authly.Policies{
    JWTClaims:    authly.ClaimPolicy{Required: []string{"sub", "exp"}},
    OpaqueClaims: authly.ClaimPolicy{Required: []string{"sub", "client_id"}},
}
```

## Lua Policy Example

Lua scripts run **after** declarative policies and enable conditional logic:

```go
Policies: authly.Policies{
    Lua: authly.LuaClaimsPolicy{
        Enabled: true,
        Script: `
            if has("actor") then
                require_claim("sub")
                require_value("iss", "https://auth.example.com")
            end
            if token_type() == "opaque" then
                require_claim("client_id")
            end
        `,
    },
}
```

Available Lua functions: `has(key)`, `get(key)`, `require_claim(key)`, `require_value(key, val)`, `require_one_of(key, {values})`, `reject(msg)`, `token_type()`, `is_jwt()`, `is_opaque()`.

## Adapter Examples

### gRPC

```go
import authlygrpc "github.com/keksclan/goAuthly/adapters/grpc"

server := grpc.NewServer(
    grpc.UnaryInterceptor(authlygrpc.UnaryServerInterceptor(engine)),
    grpc.StreamInterceptor(authlygrpc.StreamServerInterceptor(engine)),
)

// In your handler:
result := authlygrpc.ResultFromContext(ctx)
```

### Fiber

```go
import authlyfiber "github.com/keksclan/goAuthly/adapters/fiber"

app := fiber.New()
app.Use(authlyfiber.Middleware(engine))

app.Get("/protected", func(c *fiber.Ctx) error {
    result := authlyfiber.ResultFromLocals(c)
    return c.JSON(fiber.Map{"user": result.Subject})
})
```

### fasthttp

```go
import authlyfasthttp "github.com/keksclan/goAuthly/adapters/fasthttp"

handler := authlyfasthttp.Middleware(engine, func(ctx *fasthttp.RequestCtx) {
    result := authlyfasthttp.ResultFromCtx(ctx)
    ctx.WriteString("Hello, " + result.Subject)
})
fasthttp.ListenAndServe(":8080", handler)
```

All adapters support both `Bearer` and `Basic` authorization schemes automatically.

---

## Security Notes

- **Always set** `Issuer`, `Audience`, and `AllowedAlgs` to prevent token confusion attacks.
- **Opaque token cache keys** are SHA-256 hashed — raw tokens are never used as cache keys.
- **Basic Auth passwords** must be bcrypt hashes. Plaintext storage is a security violation.
- **Constant-time comparison** via bcrypt prevents timing attacks.
- **Dummy bcrypt comparison** on unknown usernames prevents user enumeration.
- **No panics** — all error paths return errors, never panic.
- See [docs/security.md](docs/security.md) for the full security model.

## Performance Notes

- JWKS keys are cached with configurable TTL (default 15 min); stale keys can be served if refresh fails.
- Introspection responses are cached briefly (default 30s) to avoid hammering the IdP.
- Basic Auth with bcrypt is intentionally slow (~60ms per check at default cost) — this is a feature, not a bug.
- No background goroutines by default; add your own refresh loop if needed.
- See [docs/performance.md](docs/performance.md) for benchmarking tips.

## Common Pitfalls

| Problem | Cause | Fix |
|---------|-------|-----|
| `unsupported auth mode` | Wrong `Mode` or `BasicAuth.Enabled` not set | Check `Config.Mode` matches your intent |
| `oauth2.jwks_url is required` | JWT mode without JWKS URL | Set `OAuth2.JWKSURL` |
| Token rejected but looks valid | Issuer/audience mismatch or clock skew | Verify `Issuer`/`Audience` match your IdP; check server clock |
| Basic auth fails in production | Plaintext password in `Users` map | Use `bcrypt.GenerateFromPassword` |
| Introspection returns active but rejected | Claim policy denying a claim | Check `Policies.TokenClaims` and Lua script |

## FAQ

**Q: Can I use goAuthly to issue tokens?**
A: No. goAuthly only verifies tokens and credentials. Use an identity provider for issuance.

**Q: Is the Engine safe for concurrent use?**
A: Yes. The Engine, default cache, and default HTTP client are all goroutine-safe.

**Q: Can I mix JWT verification and Basic Auth?**
A: Yes. Set `Mode: AuthModeOAuth2` with `BasicAuth.Enabled: true`. Use `Verify()` for tokens and `VerifyBasic()` for credentials. The adapters handle this automatically.

**Q: Why bcrypt and not argon2?**
A: bcrypt is the minimum required hash. The custom `Validator` function lets you use any hash algorithm you prefer.

**Q: Do I need to manage JWKS refresh?**
A: No. The Engine caches JWKS keys automatically with configurable TTL. Set `AllowStaleJWKS: true` for resilience.

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. In short:

1. Fork the repo and create a feature branch.
2. Write tests for any new functionality.
3. Run `go test ./...` and `go vet ./...` before submitting.
4. Keep PRs focused — one feature or fix per PR.
5. Follow existing code style and GoDoc conventions.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | High-level flows, Mermaid diagrams |
| [Configuration](docs/config.md) | Go, Lua, and JSON config examples |
| [Basic Auth](docs/basic-auth.md) | Hashed passwords, custom validators, mixed deployments |
| [Adapters](docs/adapters.md) | gRPC, Fiber, fasthttp integration |
| [Security](docs/security.md) | Threat model, timing attacks, production config |
| [Advanced Claims](docs/advanced-claims.md) | Declarative policies, Lua scripting, actor claims |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and debug steps |
| [Performance](docs/performance.md) | Caching, hot paths, benchmarking |

## License

See [LICENSE](LICENSE).
