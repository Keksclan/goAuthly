# Configuration Guide

goAuthly supports multiple configuration methods: native Go structs, Lua config files, and JSON config files.

## Go Configuration (Native Struct)

```go
package main

import (
    "github.com/keksclan/goAuthly/authly"
    "time"
)

func main() {
    cfg := authly.Config{
        Mode: authly.AuthModeOAuth2,
        OAuth2: authly.OAuth2Config{
            Mode:     authly.OAuth2JWTAndOpaque,
            Issuer:   "https://issuer.demo",
            Audience: "demo-api",
            JWKSURL:  "http://localhost:8080/.well-known/jwks.json",
            JWKS: authly.JWKSConfig{
                Auth: authly.JWKSAuth{
                    Kind:     authly.ClientAuthBasic,
                    Username: "client",
                    Password: "secret",
                },
            },
            Introspection: authly.IntrospectionConfig{
                Endpoint: "http://localhost:8080/introspect",
                Timeout:  5 * time.Second,
                Auth: authly.ClientAuth{
                    Kind:         authly.ClientAuthBasic,
                    ClientID:     "cid",
                    ClientSecret: "csecret",
                },
                TokenTransport: authly.TokenTransport{
                    Kind:  authly.TokenTransportBody,
                    Field: "token",
                },
            },
        },
        Policies: authly.Policies{
            TokenClaims: authly.ClaimPolicy{
                Required: []string{"sub"},
                Denylist: []string{"password"},
            },
            Lua: authly.LuaClaimsPolicy{
                Enabled: true,
                Script: `
                    if has("actor") then
                        require_claim("sub")
                        require_value("iss", "https://issuer.demo")
                    end
                `,
            },
        },
    }

    engine, err := authly.New(cfg)
    // use engine...
    _ = engine
    _ = err
}
```

## Lua Configuration File

Create a `.lua` config file:

```lua
return {
  mode = "oauth2",
  oauth2 = {
    mode = "jwt_and_opaque",
    issuer = "https://issuer.demo",
    audience = "demo-api",
    jwks = {
      url = "http://localhost:8080/.well-known/jwks.json",
      cache_ttl_sec = 900,
      auth = { kind="basic", username="client", password="secret" }
    },
    introspection = {
      endpoint = "http://localhost:8080/introspect",
      timeout_ms = 5000,
      auth = { kind="basic", username="cid", password="csecret" },
      token_transport = { kind="body", field="token" }
    }
  },
  policies = {
    claims = {
      required = {"sub"},
      denylist = {"password", "secret"},
    },
    lua = {
      enabled = true,
      script = [[
        if has("actor") then
          require_claim("sub")
          require_value("iss", "https://issuer.demo")
        end
      ]]
    }
  }
}
```

Load it:

```go
loader := authlyconfig.FromLuaFile("config.lua")
cfg, err := loader.Load(context.Background())
engine, err := authly.New(*cfg)
```

## JSON Configuration File

```json
{
  "mode": "oauth2",
  "oauth2": {
    "mode": "jwt_and_opaque",
    "issuer": "https://issuer.demo",
    "audience": "demo-api",
    "jwks_url": "http://localhost:8080/.well-known/jwks.json",
    "jwks": {
      "auth": { "kind": "basic", "username": "client", "password": "secret" }
    },
    "introspection": {
      "endpoint": "http://localhost:8080/introspect",
      "timeout_ms": 5000,
      "auth": { "kind": "basic", "client_id": "cid", "client_secret": "csecret" },
      "token_transport": { "kind": "body", "field": "token" }
    }
  },
  "policies": {
    "claims": { "required": ["sub"], "denylist": ["password"] },
    "lua": { "enabled": true, "script": "require_claim('sub')" }
  }
}
```

Load it:

```go
loader := authlyconfig.FromJSONFile("config.json")
cfg, err := loader.Load(context.Background())
```

## Config Loader Interface

All loaders implement:

```go
type Loader interface {
    Load(ctx context.Context) (*authly.Config, error)
}
```

Available loaders:
- `authlyconfig.FromGo(cfg)` — wraps an existing `authly.Config`
- `authlyconfig.FromLuaFile(path)` — loads from a Lua file
- `authlyconfig.FromJSONFile(path)` — loads from a JSON file

## Basic Auth Configuration

Basic Auth is configured directly in the `Config` struct. It does not support Lua or JSON config loading (the `Validator` function cannot be serialized).

### Static Users Map

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
```

### Custom Validator

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

### Mixed Mode (OAuth2 + Basic Auth)

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
        Users:   map[string]string{"svc": "$2a$10$..."},
    },
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Activates Basic Auth |
| `Users` | `map[string]string` | `nil` | Username → bcrypt hash map |
| `Validator` | `func(ctx, user, pass) (bool, error)` | `nil` | Custom credential checker (takes priority over Users) |
| `Realm` | `string` | `"Restricted"` | WWW-Authenticate realm |

See [docs/basic-auth.md](basic-auth.md) for detailed usage and security considerations.

## Token Transport Options

The introspection endpoint can receive the token via body (default) or header:

| Kind | Description |
|------|-------------|
| `body` | Token sent in POST body form field (default: `token`) |
| `header` | Token sent in request header with optional prefix |

### Body transport (default)
```go
TokenTransport: authly.TokenTransport{
    Kind:  authly.TokenTransportBody,
    Field: "token", // or "access_token"
}
```

### Header transport
```go
TokenTransport: authly.TokenTransport{
    Kind:   authly.TokenTransportHeader,
    Header: "X-Token",
    Prefix: "Bearer ",
}
```

## Client Authentication Options

Used for both introspection and JWKS endpoints:

| Kind | Description |
|------|-------------|
| `none` | No authentication |
| `basic` | HTTP Basic Authentication |
| `body` | client_id/client_secret in form body |
| `bearer` | Authorization: Bearer header |
| `header` | Custom header name/value |

## JWKS Auth Options

```go
JWKS: authly.JWKSConfig{
    Auth: authly.JWKSAuth{
        Kind:     authly.ClientAuthBasic,
        Username: "client",
        Password: "secret",
    },
    ExtraHeaders: map[string]string{
        "X-Custom": "value",
    },
}
```
