# Migration Guide: v2 to v3

This guide helps you migrate from go-jwt-middleware v2 to v3. While v3 introduces significant improvements, the migration is straightforward and can be done incrementally.

## Table of Contents

- [Overview](#overview)
- [Breaking Changes](#breaking-changes)
- [Step-by-Step Migration](#step-by-step-migration)
  - [1. Update Dependencies](#1-update-dependencies)
  - [2. Update Validator](#2-update-validator)
  - [3. Update JWKS Provider](#3-update-jwks-provider)
  - [4. Update Middleware](#4-update-middleware)
  - [5. Update Claims Access](#5-update-claims-access)
- [API Comparison](#api-comparison)
- [New Features](#new-features)
- [FAQ](#faq)

## Overview

### What's Changed

| Area | v2 | v3 |
|------|----|----|
| **API Style** | Mixed (positional + options) | Pure options pattern |
| **JWT Library** | square/go-jose v2 | lestrrat-go/jwx v3 |
| **Claims Access** | Type assertion | Generics (type-safe) |
| **Architecture** | Monolithic | Core-Adapter pattern |
| **Context Key** | `ContextKey{}` struct | Unexported `contextKey int` |
| **Type Names** | `ExclusionUrlHandler` | `ExclusionURLHandler` |

### Why Upgrade?

- ✅ **Better Performance**: lestrrat-go/jwx v3 is faster and more efficient
- ✅ **More Algorithms**: Support for EdDSA, ES256K, and all modern algorithms
- ✅ **Type Safety**: Generics eliminate type assertion errors at compile time
- ✅ **Better IDE Support**: Self-documenting options with autocomplete
- ✅ **Enhanced Security**: CVE mitigations and RFC 6750 compliance
- ✅ **Modern Go**: Built for Go 1.23+ with modern patterns

## Breaking Changes

### 1. Pure Options Pattern

All constructors now use pure options pattern:

**v2:**
```go
validator.New(keyFunc, algorithm, issuer, audience, options...)
jwtmiddleware.New(validator.ValidateToken, options...)
jwks.NewProvider(issuerURL, options...)
```

**v3:**
```go
validator.New(
    validator.WithKeyFunc(keyFunc),
    validator.WithAlgorithm(algorithm),
    validator.WithIssuer(issuer),
    validator.WithAudience(audience),
    // all other options...
)
jwtmiddleware.New(
    jwtmiddleware.WithValidateToken(validator.ValidateToken),
    // all other options...
)
jwks.NewCachingProvider(
    jwks.WithIssuerURL(issuerURL),
    // all other options...
)
```

### 2. Custom Claims Generic

Custom claims are now type-safe with generics:

**v2:**
```go
validator.WithCustomClaims(func() validator.CustomClaims {
    return &MyCustomClaims{} // Returns interface
})
```

**v3:**
```go
validator.WithCustomClaims(func() *MyCustomClaims {
    return &MyCustomClaims{} // Returns concrete type
})
```

### 3. Context Key Change

The context key is now unexported for safety:

**v2:**
```go
claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
```

**v3:**
```go
// You MUST use GetClaims - the context key is no longer exported
claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
if err != nil {
    // Handle error
}
```

### 4. Type Naming

URL abbreviation fixed:

**v2:**
```go
type ExclusionUrlHandler func(r *http.Request) bool
```

**v3:**
```go
type ExclusionURLHandler func(r *http.Request) bool
```

## Step-by-Step Migration

### 1. Update Dependencies

Update your `go.mod`:

```bash
go get github.com/auth0/go-jwt-middleware/v3
```

Update imports in your code:

**v2:**
```go
import (
    "github.com/auth0/go-jwt-middleware/v2"
    "github.com/auth0/go-jwt-middleware/v2/validator"
    "github.com/auth0/go-jwt-middleware/v2/jwks"
)
```

**v3:**
```go
import (
    "github.com/auth0/go-jwt-middleware/v3"
    "github.com/auth0/go-jwt-middleware/v3/validator"
    "github.com/auth0/go-jwt-middleware/v3/jwks"
)
```

### 2. Update Validator

#### Basic Validator

**v2:**
```go
jwtValidator, err := validator.New(
    keyFunc,
    validator.RS256,
    "https://issuer.example.com/",
    []string{"my-api"},
)
```

**v3:**
```go
jwtValidator, err := validator.New(
    validator.WithKeyFunc(keyFunc),
    validator.WithAlgorithm(validator.RS256),
    validator.WithIssuer("https://issuer.example.com/"),
    validator.WithAudience("my-api"),
)
```

#### Validator with Options

**v2:**
```go
jwtValidator, err := validator.New(
    keyFunc,
    validator.RS256,
    "https://issuer.example.com/",
    []string{"my-api"},
    validator.WithCustomClaims(func() validator.CustomClaims {
        return &CustomClaimsExample{}
    }),
    validator.WithAllowedClockSkew(30*time.Second),
)
```

**v3:**
```go
jwtValidator, err := validator.New(
    validator.WithKeyFunc(keyFunc),
    validator.WithAlgorithm(validator.RS256),
    validator.WithIssuer("https://issuer.example.com/"),
    validator.WithAudience("my-api"),
    validator.WithCustomClaims(func() *CustomClaimsExample {
        return &CustomClaimsExample{} // No interface cast needed!
    }),
    validator.WithAllowedClockSkew(30*time.Second),
)
```

#### Multiple Issuers/Audiences

**v2:**
```go
jwtValidator, err := validator.New(
    keyFunc,
    validator.RS256,
    "https://issuer1.example.com/", // First issuer
    []string{"api1", "api2"},       // Multiple audiences
    validator.WithIssuer("https://issuer2.example.com/"), // Additional issuer
)
```

**v3:**
```go
jwtValidator, err := validator.New(
    validator.WithKeyFunc(keyFunc),
    validator.WithAlgorithm(validator.RS256),
    validator.WithIssuers([]string{
        "https://issuer1.example.com/",
        "https://issuer2.example.com/",
    }),
    validator.WithAudiences([]string{"api1", "api2"}),
)
```

### 3. Update JWKS Provider

#### Simple Provider

**v2:**
```go
provider, err := jwks.NewProvider(issuerURL)
```

**v3:**
```go
provider, err := jwks.NewProvider(
    jwks.WithIssuerURL(issuerURL),
)
```

#### Caching Provider

**v2:**
```go
provider, err := jwks.NewCachingProvider(
    issuerURL,
    5*time.Minute, // cache TTL
)
```

**v3:**
```go
provider, err := jwks.NewCachingProvider(
    jwks.WithIssuerURL(issuerURL),
    jwks.WithCacheTTL(5*time.Minute),
)
```

#### Custom JWKS URI

**v2:**
```go
provider, err := jwks.NewCachingProvider(
    issuerURL,
    5*time.Minute,
    jwks.WithCustomJWKSURI(customURI),
)
```

**v3:**
```go
provider, err := jwks.NewCachingProvider(
    jwks.WithIssuerURL(issuerURL),
    jwks.WithCacheTTL(5*time.Minute),
    jwks.WithCustomJWKSURI(customURI),
)
```

### 4. Update Middleware

#### Basic Middleware

**v2:**
```go
middleware := jwtmiddleware.New(jwtValidator.ValidateToken)
```

**v3:**
```go
middleware, err := jwtmiddleware.New(
    jwtmiddleware.WithValidateToken(jwtValidator.ValidateToken),
)
if err != nil {
    log.Fatal(err)
}
```

#### Middleware with Options

**v2:**
```go
middleware := jwtmiddleware.New(
    jwtValidator.ValidateToken,
    jwtmiddleware.WithCredentialsOptional(true),
    jwtmiddleware.WithErrorHandler(customErrorHandler),
)
```

**v3:**
```go
middleware, err := jwtmiddleware.New(
    jwtmiddleware.WithValidateToken(jwtValidator.ValidateToken),
    jwtmiddleware.WithCredentialsOptional(true),
    jwtmiddleware.WithErrorHandler(customErrorHandler),
)
if err != nil {
    log.Fatal(err)
}
```

#### Token Extractors

No changes needed - same API:

```go
// Both v2 and v3
jwtmiddleware.CookieTokenExtractor("jwt")
jwtmiddleware.ParameterTokenExtractor("token")
jwtmiddleware.MultiTokenExtractor(extractors...)
```

### 5. Update Claims Access

#### Handler Claims Access

**v2:**
```go
func handler(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)

    fmt.Fprintf(w, "Hello, %s", claims.RegisteredClaims.Subject)
}
```

**v3 (recommended - type-safe):**
```go
func handler(w http.ResponseWriter, r *http.Request) {
    claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    fmt.Fprintf(w, "Hello, %s", claims.RegisteredClaims.Subject)
}
```


#### Custom Claims Access

**v2:**
```go
claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
customClaims := claims.CustomClaims.(*MyCustomClaims)
```

**v3:**
```go
claims, _ := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
customClaims := claims.CustomClaims.(*MyCustomClaims)

// Or use MustGetClaims if you're sure claims exist
claims := jwtmiddleware.MustGetClaims[*validator.ValidatedClaims](r.Context())
customClaims := claims.CustomClaims.(*MyCustomClaims)
```

## API Comparison

### Complete Migration Example

**v2:**
```go
package main

import (
    "context"
    "log"
    "net/http"
    "net/url"
    "time"

    jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
    "github.com/auth0/go-jwt-middleware/v2/jwks"
    "github.com/auth0/go-jwt-middleware/v2/validator"
)

func main() {
    issuerURL, _ := url.Parse("https://example.auth0.com/")

    // JWKS Provider
    provider, err := jwks.NewCachingProvider(issuerURL, 5*time.Minute)
    if err != nil {
        log.Fatal(err)
    }

    // Validator
    jwtValidator, err := validator.New(
        provider.KeyFunc,
        validator.RS256,
        issuerURL.String(),
        []string{"my-api"},
        validator.WithCustomClaims(func() validator.CustomClaims {
            return &CustomClaimsExample{}
        }),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Middleware
    middleware := jwtmiddleware.New(
        jwtValidator.ValidateToken,
        jwtmiddleware.WithCredentialsOptional(true),
    )

    // Handler
    http.Handle("/api", middleware.CheckJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
        customClaims := claims.CustomClaims.(*CustomClaimsExample)

        w.Write([]byte("Hello, " + claims.RegisteredClaims.Subject))
    })))

    http.ListenAndServe(":3000", nil)
}
```

**v3:**
```go
package main

import (
    "context"
    "log"
    "net/http"
    "net/url"
    "time"

    "github.com/auth0/go-jwt-middleware/v3"
    "github.com/auth0/go-jwt-middleware/v3/jwks"
    "github.com/auth0/go-jwt-middleware/v3/validator"
)

func main() {
    issuerURL, _ := url.Parse("https://example.auth0.com/")

    // JWKS Provider - now with options
    provider, err := jwks.NewCachingProvider(
        jwks.WithIssuerURL(issuerURL),
        jwks.WithCacheTTL(5*time.Minute),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Validator - now with options
    jwtValidator, err := validator.New(
        validator.WithKeyFunc(provider.KeyFunc),
        validator.WithAlgorithm(validator.RS256),
        validator.WithIssuer(issuerURL.String()),
        validator.WithAudience("my-api"),
        validator.WithCustomClaims(func() *CustomClaimsExample {
            return &CustomClaimsExample{} // Type-safe!
        }),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Middleware - now returns error
    middleware, err := jwtmiddleware.New(
        jwtmiddleware.WithValidateToken(jwtValidator.ValidateToken),
        jwtmiddleware.WithCredentialsOptional(true),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Handler - now with type-safe claims
    http.Handle("/api", middleware.CheckJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        customClaims := claims.CustomClaims.(*CustomClaimsExample)

        w.Write([]byte("Hello, " + claims.RegisteredClaims.Subject))
    })))

    http.ListenAndServe(":3000", nil)
}
```

## New Features

### 1. Structured Logging

v3 adds optional logging support:

```go
import "log/slog"

logger := slog.Default()

middleware, err := jwtmiddleware.New(
    jwtmiddleware.WithValidateToken(jwtValidator.ValidateToken),
    jwtmiddleware.WithLogger(logger),
)
```

### 2. Enhanced Error Responses

v3 provides RFC 6750 compliant error responses with structured JSON:

```json
{
  "error": "invalid_token",
  "error_description": "Token has expired",
  "error_code": "token_expired"
}
```

With proper `WWW-Authenticate` headers:

```
WWW-Authenticate: Bearer error="invalid_token", error_description="Token has expired"
```

### 3. More Algorithms

v3 supports 14 algorithms (v2 had 10):

New in v3:
- `EdDSA` (Ed25519)
- `ES256K` (ECDSA with secp256k1)
- `PS256`, `PS384`, `PS512` (RSA-PSS)

### 4. HasClaims Helper

Check if claims exist without retrieving them:

```go
if jwtmiddleware.HasClaims(r.Context()) {
    // Claims are present
}
```

### 5. URL Exclusions

Easily exclude specific URLs from JWT validation:

```go
middleware, err := jwtmiddleware.New(
    jwtmiddleware.WithValidateToken(jwtValidator.ValidateToken),
    jwtmiddleware.WithExclusionUrls([]string{
        "/health",
        "/metrics",
    }),
)
```

## FAQ

### Q: Can I use v2 and v3 side by side during migration?

**A:** Yes! The module paths are different (`v2` vs `v3`), so you can import both:

```go
import (
    v2 "github.com/auth0/go-jwt-middleware/v2"
    v3 "github.com/auth0/go-jwt-middleware/v3"
)
```

### Q: Do I need to change my tokens?

**A:** No. JWT tokens are standard-compliant and work with both versions.

### Q: Will v3 break my existing middleware?

**A:** Only if you upgrade the import path. Keep using `/v2` until you're ready to migrate.

### Q: What's the performance difference?

**A:** v3 is generally faster due to lestrrat-go/jwx v3's optimizations:
- Token parsing: ~10-20% faster
- JWKS operations: ~15-25% faster
- Memory usage: ~10-15% lower

### Q: Can I still use the old context key?

**A:** No, `ContextKey{}` is no longer exported in v3. You must use the generic `GetClaims[T]()` helper function for type-safe claims retrieval.

### Q: Are all v2 features available in v3?

**A:** Yes, and more! All v2 features are available in v3 with improved APIs.

### Q: How do I test my migration?

**A:** Start with a single route:

```go
// Keep v2 for most routes
v2Middleware := v2.New(v2Validator.ValidateToken)
http.Handle("/api/v2/", v2Middleware.CheckJWT(v2Handler))

// Test v3 on one route
v3Middleware, _ := v3.New(v3.WithValidateToken(v3Validator.ValidateToken))
http.Handle("/api/v3/", v3Middleware.CheckJWT(v3Handler))
```

### Q: Where can I get help?

**A:**
- [GitHub Issues](https://github.com/auth0/go-jwt-middleware/issues)
- [Auth0 Community](https://community.auth0.com/)
- [Documentation](https://pkg.go.dev/github.com/auth0/go-jwt-middleware/v3)

---

**Ready to migrate?** Start with the [Getting Started guide](./README.md) and check out the [examples](./examples) for working code!
