# Architecture

This document outlines how goAuthly verifies tokens and where pluggable components fit. All flows below are library-only — no adapters or servers are included.

## High-level Flow (Mermaid)

```mermaid
flowchart TD
    A[Engine.Verify(token)] --> B{Detect type}
    B -->|JWT| C[verifyJWT]
    B -->|Opaque| D[verifyOpaque]
    C --> E[JWT Validator]
    E --> F[Get key by kid from JWK Manager]
    F --> G[Verify signature + claims]
    G --> H[Policies: claims + actor]
    D --> I[Introspection client]
    I --> J[Cache by token hash]
    J --> K[Parse response -> claims]
    K --> H
    H --> L[Result]
```

## JWT Flow (Mermaid)

```mermaid
sequenceDiagram
    participant App
    participant Engine
    participant JWT as JWT Validator
    participant JWK as JWKS Manager

    App->>Engine: Verify(ctx, jwt)
    Engine->>JWT: Validate(ctx, token)
    JWT->>JWT: Parse header (kid, alg)
    JWT->>JWK: GetKey(ctx, kid)
    JWK-->>JWT: rsa/ecdsa public key
    JWT->>JWT: Verify signature + times + aud/iss
    Engine->>Engine: Policies (claims, actor)
    Engine-->>App: Result
```

## Opaque Flow (Mermaid)

```mermaid
sequenceDiagram
    participant App
    participant Engine
    participant INT as Introspection Client
    participant Cache

    App->>Engine: Verify(ctx, opaque)
    Engine->>Cache: Lookup(hash(token))
    Cache-->>Engine: hit/miss
    Engine->>INT: POST /introspect
    INT-->>Engine: IntrospectionResponse
    Engine->>Cache: Store(active only)
    Engine->>Engine: Convert to claims
    Engine->>Engine: Policies (claims, actor)
    Engine-->>App: Result
```

## Policy Validation Flow (Mermaid)

```mermaid
flowchart LR
    A[Claims map] --> B{Required}
    B -->|missing| X[Error]
    B -->|ok| C{Denylist}
    C -->|present| X
    C -->|ok| D{Allowlist}
    D -->|unknown claim| X
    D -->|ok| E{Enforced values}
    E -->|violation| X
    E -->|ok| F[Actor extraction + checks]
    F -->|violation| X
    F -->|ok| G[Success]
```

## Components

- Engine: orchestrates verification, caches, and policies.
- JWT Validator: parses and validates JWTs; gets keys via JWK Manager.
- JWK Manager: fetches and caches JWKS; supports stale reads when enabled.
- Introspection Client: calls RFC 7662 endpoint and maps extras.
- Cache: minimal TTL cache abstraction used for JWKS and introspection.

## Token Type Semantics

- JWT tokens follow RFC 7519 semantics: signature verification, standard time claims, issuer/audience checks. There is no `active` concept for JWTs.
- Opaque tokens follow RFC 7662 introspection semantics: the response must include `active` and, by default, it must be `true` to accept the token. Other fields are treated as claims.
- The Engine now separates verification paths internally via distinct verifiers and policies per token type.
- The `Result` exposes the token type and the source pipeline used: `Type` is `jwt` or `opaque`, and `Source` is `jwt` or `introspection`.
- The `active` attribute exists only for opaque (introspection) and is validated internally. Unless explicitly configured to expose, it is removed from `Result.Claims` after validation.

```mermaid
flowchart TD
    Token --> DetectType
    DetectType -->|JWT| JWTVerifier
    DetectType -->|Opaque| OpaqueVerifier
    JWTVerifier --> JWTPolicies
    OpaqueVerifier --> ActiveCheck
    ActiveCheck --> OpaquePolicies
    JWTPolicies --> Result
    OpaquePolicies --> Result
```
