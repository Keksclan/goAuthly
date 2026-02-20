# goAuthly

Lightweight, focused token verification for Go services. Supports OAuth2 JWT and opaque tokens with JWKS fetching and RFC 7662 introspection.

## Quick Start

Run the end-to-end example locally:

```
go run ./examples/verify_demo
```

The example spins up a local HTTP server that:
- Serves a JWKS at `/.well-known/jwks.json`
- Implements an introspection endpoint at `/introspect`
- Mints a signed JWT and demonstrates verifying both a JWT and an opaque token

Explore the example source at `examples/verify_demo` for a complete, minimal setup.

## API Overview

Create an `Engine` with a `Config`:

```go
eng, err := authly.New(authly.Config{ /* ... */ })
res, err := eng.Verify(ctx, token)
```

The returned `Result` includes the token type (JWT or opaque), subject, optional actor, scopes, expiration, and all raw claims.

### Modes

`OAuth2Mode` controls which token types are accepted:
- `jwt_only`: accept only JWTs
- `opaque_only`: accept only opaque tokens via introspection
- `jwt_and_opaque`: accept both; detection is O(1) via `.` count

### JWKS & Introspection

- JWKS: keys are fetched and cached with configurable TTL; optionally serve stale keys if refresh fails.
- Introspection: RFC 7662 responses are cached briefly by a SHA-256 hash of the opaque token (no raw tokens used as cache keys).

### Policies

`ClaimPolicy` lets you:
- Require certain claims (e.g., `sub`)
- Deny claims
- Allowlist known claims to reject unknown ones
- Enforce allowed values for selected claims

### Actor

`ActorPolicy` enables extraction and validation of an "actor" (RFC 8693 style) from a configurable claim (default `sub` field inside the actor object). You can restrict allowed actor subjects.

## Thread Safety

`Engine` is safe for concurrent use with the default cache and HTTP client. `Config` should be treated as immutable after construction.

## Security Notes

- Always set expected `issuer`, `audience`, and allowed algorithms.
- Use allowlists where feasible to reject unexpected claims.
- Opaque token cache keys are hashed to avoid storing raw secrets.

## Config Options

goAuthly supports loading configuration from Go structs, Lua files, or JSON files via the `authlyconfig` package.

### Minimal Go Config

```go
cfg := authly.Config{
    Mode: authly.AuthModeOAuth2,
    OAuth2: authly.OAuth2Config{
        Mode:     authly.OAuth2JWTAndOpaque,
        Issuer:   "https://issuer.demo",
        Audience: "demo-api",
        JWKSURL:  "http://localhost:8080/.well-known/jwks.json",
        Introspection: authly.IntrospectionConfig{
            Endpoint: "http://localhost:8080/introspect",
        },
    },
}
engine, err := authly.New(cfg)
```

### Minimal Lua Config

```lua
return {
  mode = "oauth2",
  oauth2 = {
    mode = "jwt_and_opaque",
    jwks = { url = "http://localhost/.well-known/jwks.json" },
    introspection = { endpoint = "http://localhost/introspect" }
  }
}
```

Load with: `authlyconfig.FromLuaFile("config.lua")`

### Lua Claim Rules

Lua scripts run after declarative policies and support conditional logic:

```lua
if has("actor") then
    require_claim("sub")
    require_value("iss", "https://issuer.demo")
end
if has("xy") then
    require_claim("x")
    require_one_of("x", {"a", "b", "c"})
end
```

### Token Transport for Introspection

Send the token in the body (default) or a header:

```go
// Body (default, RFC 7662)
TokenTransport: authly.TokenTransport{Kind: authly.TokenTransportBody, Field: "token"}

// Header
TokenTransport: authly.TokenTransport{Kind: authly.TokenTransportHeader, Header: "X-Token", Prefix: "Bearer "}
```

### JWKS Auth Options

Authenticate JWKS fetches with Basic, Bearer, or custom headers:

```go
JWKS: authly.JWKSConfig{
    Auth: authly.JWKSAuth{Kind: authly.ClientAuthBasic, Username: "u", Password: "p"},
    ExtraHeaders: map[string]string{"X-Custom": "value"},
}
```

See `docs/config.md` and `docs/claims.md` for full details.

## See Also

- `docs/architecture.md` — high-level and detailed flows (Mermaid)
- `docs/performance.md` — caching strategy and hot paths
- `docs/config.md` — Go, Lua, and JSON configuration examples
- `docs/claims.md` — declarative and Lua policy examples with diagrams
- `examples/verify_demo` — runnable end-to-end example
