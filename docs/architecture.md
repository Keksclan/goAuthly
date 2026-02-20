# Architecture

This document outlines the architecture of the goAuthly library.

## Overview

goAuthly is designed to be a lightweight, decoupled library for authorization verification. It follows a clean architecture approach, separating core logic from infrastructure and framework concerns.

## Components

- **Core**: Contains the central authorization verification logic.
- **OAuth**: Implements OAuth 2.0 token verification.
- **Basic**: Implements basic authentication verification.
- **Cache**: Provides mechanisms for caching verification results and JWKs.
- **JWK**: Handles fetching and parsing of JSON Web Keys.
- **Adapters**: Provides integration layers for various Go frameworks (gRPC, Fiber, FastHTTP).
- **Types**: Defines shared data structures and types used across the library.
