# goAuthly

Lightweight authorization verification library for Go microservices.

## Goals

- Provide a simple and efficient way to verify authorization in Go microservices.
- Support multiple authorization methods (OAuth, Basic auth, etc.).
- Maintain high performance and low overhead.
- Ensure easy integration with popular Go frameworks.

## Non-goals

- Implementing authentication services.
- Providing identity management or user storage.
- Handling session management beyond verification.

## Planned Features

- OAuth token verification.
- Basic authentication support.
- JWK (JSON Web Key) fetching and caching.
- Integration adapters for gRPC, Fiber, and FastHTTP.
- Flexible caching mechanisms for verification results.

## Design Philosophy

- Simplicity and clarity in API design.
- Minimalism: include only what is necessary.
- Robustness: handle edge cases and errors gracefully.
- Decoupling: separate core logic from framework-specific adapters.

## Development Rule

Only implement what is explicitly requested.

## Status

Early stage
