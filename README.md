![Go JWT Middleware](https://cdn.auth0.com/website/sdks/banners/go-jwt-middleware.png)

<div align="center">

[![GoDoc](https://pkg.go.dev/badge/github.com/auth0/go-jwt-middleware.svg)](https://pkg.go.dev/github.com/auth0/go-jwt-middleware/v3)
[![Go Report Card](https://goreportcard.com/badge/github.com/auth0/go-jwt-middleware/v3?style=flat-square)](https://goreportcard.com/report/github.com/auth0/go-jwt-middleware/v3)
[![License](https://img.shields.io/github/license/auth0/go-jwt-middleware.svg?logo=fossa&style=flat-square)](https://github.com/auth0/go-jwt-middleware/blob/master/LICENSE)
[![Release](https://img.shields.io/github/v/release/auth0/go-jwt-middleware?include_prereleases&style=flat-square)](https://github.com/auth0/go-jwt-middleware/releases)
[![Codecov](https://img.shields.io/codecov/c/github/auth0/go-jwt-middleware?logo=codecov&style=flat-square&token=fs2WrOXe9H)](https://codecov.io/gh/auth0/go-jwt-middleware)
[![Tests](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fauth0%2Fgo-jwt-middleware%2Fbadge%3Fref%3Dmaster&style=flat-square)](https://github.com/auth0/go-jwt-middleware/actions?query=branch%3Amaster)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/auth0/go-jwt-middleware)

📚 [Documentation](#documentation) • 🚀 [Getting Started](#getting-started) • ✨ [What's New in v3](#whats-new-in-v3) • 💬 [Feedback](#feedback)
</div>

## Documentation

- [Godoc](https://pkg.go.dev/github.com/auth0/go-jwt-middleware/v3) - explore the go-jwt-middleware documentation.
- [Docs site](https://www.auth0.com/docs) — explore our docs site and learn more about Auth0.
- [Quickstart](https://auth0.com/docs/quickstart/backend/golang/interactive) - our guide for adding go-jwt-middleware to your app.
- [Migration Guide](./MIGRATION.md) - upgrading from v2 to v3.

## What's New in v3

v3 introduces significant improvements while maintaining the simplicity and flexibility you expect:

### 🎯 Pure Options Pattern
All configuration through functional options for better IDE support and compile-time validation:

```go
// v3: Clean, self-documenting API
validator.New(
    validator.WithKeyFunc(keyFunc),
    validator.WithAlgorithm(validator.RS256),
    validator.WithIssuer("https://issuer.example.com/"),
    validator.WithAudience("my-api"),
)
```

### 🔐 Enhanced JWT Library (lestrrat-go/jwx v3)
- Better performance and security
- Support for 14 signature algorithms (including EdDSA, ES256K)
- Improved JWKS handling with automatic `kid` matching
- Active maintenance and modern Go support

### 🏗️ Core-Adapter Architecture
Framework-agnostic validation logic that can be reused across HTTP, gRPC, and other transports:

```
HTTP Middleware → Core Engine → Validator
```

### 🎁 Type-Safe Claims with Generics
Use Go 1.24+ generics for compile-time type safety:

```go
claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
```

### 📊 Built-in Logging Support
Optional structured logging compatible with `log/slog`:

```go
jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithLogger(slog.Default()),
)
```

### 🛡️ Enhanced Security
- RFC 6750 compliant error responses
- Secure defaults (credentials required, clock skew = 0)
- **DPoP support** (RFC 9449) for proof-of-possession tokens

### 🔑 DPoP (Demonstrating Proof-of-Possession)
Prevent token theft with proof-of-possession:

```go
jwtmiddleware.New(
    jwtmiddleware.WithValidator(jwtValidator),
    jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPRequired),
)
```

## Getting Started

### Requirements

This library follows the [same support policy as Go](https://go.dev/doc/devel/release#policy). The last two major Go releases are actively supported and compatibility issues will be fixed.

- **Go 1.24+**

### Installation

```shell
go get github.com/auth0/go-jwt-middleware/v3
```

### Basic Usage

#### Simple Example with HMAC

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Type-safe claims retrieval with generics
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	if err != nil {
		http.Error(w, "failed to get claims", http.StatusInternalServerError)
		return
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

func main() {
	keyFunc := func(ctx context.Context) (any, error) {
		// Our token must be signed using this secret
		return []byte("secret"), nil
	}

	// Create validator with options pattern
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer("go-jwt-middleware-example"),
		validator.WithAudience("audience-example"),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Create middleware with options pattern
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	http.ListenAndServe("0.0.0.0:3000", middleware.CheckJWT(handler))
}
```

**Try it out:**
```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.XFhrzWzntyINkgoRt2mb8dES84dJcuOoORdzKfwUX70" \
  http://localhost:3000
```

This JWT is signed with `secret` and contains:
```json
{
  "iss": "go-jwt-middleware-example",
  "aud": "audience-example",
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "username": "user123"
}
```

#### Production Example with JWKS and Auth0

```go
package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

func main() {
	issuerURL, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/")
	if err != nil {
		log.Fatalf("failed to parse issuer URL: %v", err)
	}

	// Create JWKS provider with caching
	provider, err := jwks.NewCachingProvider(
		jwks.WithIssuerURL(issuerURL),
	)
	if err != nil {
		log.Fatalf("failed to create JWKS provider: %v", err)
	}

	// Create validator
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuer(issuerURL.String()),
		validator.WithAudience(os.Getenv("AUTH0_AUDIENCE")),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Create middleware
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	// Protected route
	http.Handle("/api/private", middleware.CheckJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
		w.Write([]byte("Hello, " + claims.RegisteredClaims.Subject))
	})))

	// Public route
	http.HandleFunc("/api/public", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, anonymous user"))
	})

	log.Println("Server listening on :3000")
	http.ListenAndServe(":3000", nil)
}
```

### Testing the Server

After running the server (`go run main.go`), test with curl:

**Valid Token:**
```bash
$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.XFhrzWzntyINkgoRt2mb8dES84dJcuOoORdzKfwUX70" localhost:3000
```

Response:
```json
{
  "CustomClaims": null,
  "RegisteredClaims": {
    "iss": "go-jwt-middleware-example",
    "aud": ["audience-example"],
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
  }
}
```

**Invalid Token:**
```bash
$ curl -v -H "Authorization: Bearer invalid.token.here" localhost:3000
```

Response:
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer error="invalid_token", error_description="The access token is invalid"

{
  "error": "invalid_token",
  "error_description": "The access token is invalid"
}
```

## Advanced Usage

### Custom Claims

Define and validate custom claims:

```go
type CustomClaims struct {
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"`
}

func (c *CustomClaims) Validate(ctx context.Context) error {
	if c.Scope == "" {
		return errors.New("scope is required")
	}
	return nil
}

// Use with validator
jwtValidator, err := validator.New(
	validator.WithKeyFunc(keyFunc),
	validator.WithAlgorithm(validator.RS256),
	validator.WithIssuer("https://issuer.example.com/"),
	validator.WithAudience("my-api"),
	validator.WithCustomClaims(func() *CustomClaims {
		return &CustomClaims{}
	}),
)

// Access in handler
func handler(w http.ResponseWriter, r *http.Request) {
	claims, _ := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	customClaims := claims.CustomClaims.(*CustomClaims)

	if contains(customClaims.Permissions, "read:data") {
		// User has permission
	}
}
```

### Optional Credentials

Allow both authenticated and public access:

```go
middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithCredentialsOptional(true),
)

func handler(w http.ResponseWriter, r *http.Request) {
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	if err != nil {
		// No JWT - serve public content
		w.Write([]byte("Public content"))
		return
	}
	// JWT present - serve authenticated content
	w.Write([]byte("Hello, " + claims.RegisteredClaims.Subject))
}
```

### Custom Token Extraction

Extract tokens from cookies or query parameters:

```go
// From cookie
middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithTokenExtractor(jwtmiddleware.CookieTokenExtractor("jwt")),
)

// From query parameter
middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithTokenExtractor(jwtmiddleware.ParameterTokenExtractor("token")),
)

// Try multiple sources
middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithTokenExtractor(jwtmiddleware.MultiTokenExtractor(
		jwtmiddleware.AuthHeaderTokenExtractor,
		jwtmiddleware.CookieTokenExtractor("jwt"),
	)),
)
```

### URL Exclusions

Skip JWT validation for specific URLs:

```go
middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithExclusionUrls([]string{
		"/health",
		"/metrics",
		"/public",
	}),
)
```

### Structured Logging

Enable logging with `log/slog` or compatible loggers:

```go
import "log/slog"

logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelDebug,
}))

middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithLogger(logger),
)
```

### Custom Error Handling

Implement custom error responses:

```go
func customErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("JWT error: %v", err)

	if errors.Is(err, jwtmiddleware.ErrJWTMissing) {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	var validationErr *core.ValidationError
	if errors.As(err, &validationErr) {
		switch validationErr.Code {
		case core.ErrorCodeTokenExpired:
			http.Error(w, "Token expired", http.StatusUnauthorized)
		default:
			http.Error(w, "Invalid token", http.StatusUnauthorized)
		}
		return
	}

	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithErrorHandler(customErrorHandler),
)
```

### Clock Skew Tolerance

Allow for time drift between servers:

```go
jwtValidator, err := validator.New(
	validator.WithKeyFunc(keyFunc),
	validator.WithAlgorithm(validator.RS256),
	validator.WithIssuer("https://issuer.example.com/"),
	validator.WithAudience("my-api"),
	validator.WithAllowedClockSkew(30*time.Second),
)
```

### DPoP (Demonstrating Proof-of-Possession)

v3 adds support for [DPoP (RFC 9449)](https://datatracker.ietf.org/doc/html/rfc9449), which provides proof-of-possession for access tokens. This prevents token theft and replay attacks.

#### DPoP Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **DPoPAllowed** (default) | Accepts both Bearer and DPoP tokens | Migration period, backward compatibility |
| **DPoPRequired** | Only accepts DPoP tokens | Maximum security |
| **DPoPDisabled** | Ignores DPoP proofs, rejects DPoP scheme | Legacy systems |

#### Basic DPoP Setup

```go
middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPAllowed), // Default
)
```

#### Require DPoP for Maximum Security

```go
middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPRequired),
)
```

#### Behind a Proxy

When running behind a reverse proxy, configure trusted proxy headers:

```go
middleware, err := jwtmiddleware.New(
	jwtmiddleware.WithValidator(jwtValidator),
	jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPRequired),
	jwtmiddleware.WithStandardProxy(),  // Trust X-Forwarded-* headers
)
```

See the [DPoP examples](./examples/http-dpop-example) for complete working code.

## Examples

For complete working examples, check the [examples](./examples) directory:

- **[http-example](./examples/http-example)** - Basic HTTP server with HMAC
- **[http-jwks-example](./examples/http-jwks-example)** - Production setup with JWKS and Auth0
- **[http-dpop-example](./examples/http-dpop-example)** - DPoP support (allowed mode)
- **[http-dpop-required](./examples/http-dpop-required)** - DPoP required mode
- **[http-dpop-disabled](./examples/http-dpop-disabled)** - DPoP disabled mode
- **[http-dpop-trusted-proxy](./examples/http-dpop-trusted-proxy)** - DPoP behind reverse proxy
- **[gin-example](./examples/gin-example)** - Integration with Gin framework
- **[echo-example](./examples/echo-example)** - Integration with Echo framework
- **[iris-example](./examples/iris-example)** - Integration with Iris framework

## Supported Algorithms

v3 supports 14 signature algorithms:

| Type | Algorithms |
|------|-----------|
| HMAC | HS256, HS384, HS512 |
| RSA | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384, ES512, ES256K |
| EdDSA | EdDSA (Ed25519) |

## Migration from v2

See [MIGRATION.md](./MIGRATION.md) for a complete guide on upgrading from v2 to v3.

Key changes:
- Pure options pattern for all components
- Type-safe claims with generics
- New JWT library (lestrrat-go/jwx v3)
- Core-Adapter architecture

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Contribution Guide](./CONTRIBUTING.md)
- [Auth0's General Contribution Guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's Code of Conduct Guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)

### Raise an issue

To provide feedback or report a bug, [please raise an issue on our issue tracker](https://github.com/auth0/go-jwt-middleware/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public Github issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>

<p align="center">Auth0 is an easy to implement, adaptable authentication and authorization platform.<br />To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>

<p align="center">This project is licensed under the MIT license. See the <a href="./LICENSE.md"> LICENSE</a> file for more info.</p>
