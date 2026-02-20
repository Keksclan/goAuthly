# Adapters

goAuthly ships with thin transport adapters for **gRPC**, **Fiber**, and **fasthttp**. Each adapter does exactly three things:

1. Extracts the `Authorization` header.
2. Calls `Engine.Verify()` (Bearer) or `Engine.VerifyBasic()` (Basic).
3. Injects the `Result` into the framework's context mechanism.

No business logic. No claim checking. No caching. That's the Engine's job.

---

## gRPC Adapter

**Package:** `github.com/keksclan/goAuthly/adapters/grpc`

### Unary Interceptor

```go
import authlygrpc "github.com/keksclan/goAuthly/adapters/grpc"

server := grpc.NewServer(
    grpc.UnaryInterceptor(authlygrpc.UnaryServerInterceptor(engine)),
)
```

### Stream Interceptor

```go
server := grpc.NewServer(
    grpc.StreamInterceptor(authlygrpc.StreamServerInterceptor(engine)),
)
```

### Both Together

```go
server := grpc.NewServer(
    grpc.UnaryInterceptor(authlygrpc.UnaryServerInterceptor(engine)),
    grpc.StreamInterceptor(authlygrpc.StreamServerInterceptor(engine)),
)
```

### Extracting the Result

```go
func (s *myServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
    result := authlygrpc.ResultFromContext(ctx)
    if result == nil {
        return nil, status.Error(codes.Unauthenticated, "no auth result")
    }
    log.Printf("Authenticated: %s (type: %s)", result.Subject, result.Type)
    // ...
}
```

### How It Works

The interceptor reads the `authorization` metadata key from the incoming gRPC context:

- `Bearer <token>` → calls `engine.Verify(ctx, token)`
- `Basic <base64(user:pass)>` → decodes and calls `engine.VerifyBasic(ctx, user, pass)`

On failure, it returns `codes.Unauthenticated` with the error message. On success, the `Result` is stored in the context via `context.WithValue`.

### Client-Side: Sending Credentials

```go
// Bearer token
ctx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

// Basic auth
encoded := base64.StdEncoding.EncodeToString([]byte("user:pass"))
ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Basic "+encoded)
```

---

## Fiber Adapter

**Package:** `github.com/keksclan/goAuthly/adapters/fiber`

### Middleware

```go
import authlyfiber "github.com/keksclan/goAuthly/adapters/fiber"

app := fiber.New()
app.Use(authlyfiber.Middleware(engine))
```

### Extracting the Result

```go
app.Get("/protected", func(c *fiber.Ctx) error {
    result := authlyfiber.ResultFromLocals(c)
    if result == nil {
        return c.SendStatus(401)
    }
    return c.JSON(fiber.Map{
        "user":    result.Subject,
        "type":    result.Type,
        "claims":  result.Claims,
    })
})
```

### How It Works

The middleware reads the `Authorization` HTTP header:

- `Bearer <token>` → calls `engine.Verify(ctx, token)`
- `Basic <base64(user:pass)>` → decodes and calls `engine.VerifyBasic(ctx, user, pass)`

On success, the result is stored via `c.Locals("authly", result)`. On failure, a 401 JSON response is returned:

```json
{"error": "invalid credentials"}
```

### Selective Route Protection

```go
app := fiber.New()

// Public routes
app.Get("/health", healthHandler)

// Protected routes
protected := app.Group("/api", authlyfiber.Middleware(engine))
protected.Get("/users", usersHandler)
protected.Get("/profile", profileHandler)
```

---

## fasthttp Adapter

**Package:** `github.com/keksclan/goAuthly/adapters/fasthttp`

### Middleware

```go
import authlyfasthttp "github.com/keksclan/goAuthly/adapters/fasthttp"

handler := authlyfasthttp.Middleware(engine, func(ctx *fasthttp.RequestCtx) {
    result := authlyfasthttp.ResultFromCtx(ctx)
    ctx.WriteString("Hello, " + result.Subject)
})

fasthttp.ListenAndServe(":8080", handler)
```

### Extracting the Result

```go
func protectedHandler(ctx *fasthttp.RequestCtx) {
    result := authlyfasthttp.ResultFromCtx(ctx)
    if result == nil {
        ctx.SetStatusCode(401)
        return
    }
    fmt.Fprintf(ctx, "Authenticated as %s", result.Subject)
}
```

### How It Works

The middleware wraps a `fasthttp.RequestHandler`. It reads the `Authorization` header, authenticates, and stores the result via `ctx.SetUserValue("authly", result)`.

On failure, a 401 JSON response is written:

```json
{"error": "missing authorization header"}
```

The user value key is available as the constant `authlyfasthttp.ResultUserValueKey`.

---

## Supported Authorization Schemes

All adapters support the same schemes:

| Scheme | Header Value | Engine Method |
|--------|-------------|---------------|
| Bearer | `Bearer <token>` | `engine.Verify(ctx, token)` |
| Basic  | `Basic <base64(user:pass)>` | `engine.VerifyBasic(ctx, user, pass)` |

Unsupported schemes (e.g., `Digest`, `HOBA`) return an "unsupported authorization scheme" error.

## Error Handling

| Adapter | Success | Failure |
|---------|---------|---------|
| gRPC | Result in context | `codes.Unauthenticated` status |
| Fiber | `c.Locals("authly")` set | 401 JSON `{"error": "..."}` |
| fasthttp | `ctx.UserValue("authly")` set | 401 JSON `{"error": "..."}` |

## Writing Your Own Adapter

If you use a framework not covered here (e.g., `net/http`, Chi, Echo), the pattern is simple:

```go
func MyMiddleware(engine *authly.Engine) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")

        var result *authly.Result
        var err error

        switch {
        case strings.HasPrefix(auth, "Bearer "):
            result, err = engine.Verify(r.Context(), auth[7:])
        case strings.HasPrefix(auth, "Basic "):
            // decode base64, split on ":", call engine.VerifyBasic
        default:
            http.Error(w, "unsupported scheme", 401)
            return
        }

        if err != nil {
            http.Error(w, err.Error(), 401)
            return
        }

        ctx := context.WithValue(r.Context(), "authly", result)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

The key rules: extract credentials, call Engine, inject result. Don't add logic.
