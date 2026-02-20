# fasthttp Server Example

<p align="center"><img src="../../img.png" alt="Schnallbert" width="128" /><br/><em>Schnallbert says: "Raw speed, solid auth — no compromises!"</em></p>

A minimal [fasthttp](https://github.com/valyala/fasthttp) server demonstrating goAuthly authentication middleware.

## What it demonstrates

- **JWT verification** — Bearer tokens validated against a local JWKS endpoint.
- **Opaque token verification** — Bearer tokens introspected via a local RFC 7662 endpoint.
- **Basic Auth** — Username/password verified with bcrypt.
- **Required metadata** — The `X-User-Sub` header must be present on protected routes.

## How to run

```bash
cd examples/fasthttp-server
go run .
```

The server starts on **:8082** and prints example tokens to the console:

```
=== Example Tokens ===
JWT: eyJhbGciOi...
Opaque: opaque-good
```

## Routes

| Path         | Auth             |
|--------------|------------------|
| `/public`    | None             |
| `/protected` | Bearer + X-User-Sub header |
| `/basic`     | Basic            |

## Testing with curl

Replace `<JWT>` with the token printed at startup.

### Public endpoint (no auth)

```bash
curl http://localhost:8082/public
```

### Protected endpoint with JWT

```bash
curl -H "Authorization: Bearer <JWT>" \
     -H "X-User-Sub: demo-user" \
     http://localhost:8082/protected
```

### Protected endpoint with opaque token

```bash
curl -H "Authorization: Bearer opaque-good" \
     -H "X-User-Sub: demo-user" \
     http://localhost:8082/protected
```

### Basic auth endpoint

```bash
curl -u demo:password \
     http://localhost:8082/basic
```

### Expected failure (missing X-User-Sub)

```bash
curl -H "Authorization: Bearer <JWT>" \
     http://localhost:8082/protected
# Returns 401
```

## Notes

- RSA keys are generated at startup — tokens are only valid for the current process.
- Credentials (`demo` / `password`) are for demonstration only. Never use them in production.
- A mock JWKS and introspection server runs on `127.0.0.1:9091` alongside the fasthttp app.
