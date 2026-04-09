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
- [Migration Guide](./MIGRATION_GUIDE.md) - upgrading from v2 to v3.

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
WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token is malformed"

{
  "error": "invalid_token",
  "error_description": "The access token is malformed",
  "error_code": "token_malformed"
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

	var validationErr *jwtmiddleware.ValidationError
	if errors.As(err, &validationErr) {
		switch validationErr.Code {
		case jwtmiddleware.ErrorCodeTokenExpired:
			http.Error(w, "Token expired", http.StatusUnauthorized)
		case jwtmiddleware.ErrorCodeInvalidIssuer:
			http.Error(w, "Untrusted issuer", http.StatusUnauthorized)
		case jwtmiddleware.ErrorCodeInvalidAudience:
			http.Error(w, "Audience mismatch", http.StatusUnauthorized)
		case jwtmiddleware.ErrorCodeInvalidSignature:
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
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

### Error Responses

The default error handler returns specific HTTP status codes and structured JSON responses for each type of JWT validation failure:

| Failure | HTTP Status | `error` | `error_code` |
|---------|------------|---------|-------------|
| Malformed token | 401 | `invalid_token` | `token_malformed` |
| Invalid algorithm | 401 | `invalid_token` | `invalid_algorithm` |
| Invalid signature | 401 | `invalid_token` | `invalid_signature` |
| Expired token | 401 | `invalid_token` | `token_expired` |
| Not yet valid (nbf/iat) | 401 | `invalid_token` | `token_not_yet_valid` |
| Invalid issuer | 401 | `invalid_token` | `invalid_issuer` |
| Invalid audience | 401 | `invalid_token` | `invalid_audience` |
| Invalid claims | 401 | `invalid_token` | `invalid_claims` |
| JWKS fetch failed | 401 | `invalid_token` | `jwks_fetch_failed` |
| JWKS key not found | 401 | `invalid_token` | `jwks_key_not_found` |
| Missing token | 401 | `invalid_token` | — |

Example response for an expired token:
```json
{
  "error": "invalid_token",
  "error_description": "The access token expired",
  "error_code": "token_expired"
}
```

All error responses include RFC 6750 compliant `WWW-Authenticate` headers.

**Available error code constants** (on the `jwtmiddleware` package):

`ErrorCodeTokenMalformed`, `ErrorCodeTokenExpired`, `ErrorCodeTokenNotYetValid`,
`ErrorCodeInvalidSignature`, `ErrorCodeInvalidAlgorithm`, `ErrorCodeInvalidIssuer`,
`ErrorCodeInvalidAudience`, `ErrorCodeInvalidClaims`, `ErrorCodeJWKSFetchFailed`,
`ErrorCodeJWKSKeyNotFound`

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

### Multiple Issuers (Multi-Tenant Support)

Accept JWTs from multiple issuers simultaneously - perfect for multi-tenant SaaS applications, domain migrations, or enterprise deployments.

#### When to Use What

Choose the right issuer validation approach for your use case:

| Approach | When to Use | Example Use Case |
|----------|-------------|------------------|
| **`WithIssuer`** (single) | You have one Auth0 tenant or identity provider | Simple API with single Auth0 tenant |
| **`WithIssuers`** (static list) | You have a fixed set of issuers known at startup | - Small number of tenants (< 10)<br>- Rarely changing issuer list<br>- Domain migration (old + new) |
| **`WithIssuersResolver`** (dynamic) | Issuers determined at request time from database/context | - Multi-tenant SaaS with 100s+ tenants<br>- Tenant-specific issuer configuration<br>- Dynamic tenant onboarding |

**Performance Comparison:**

- **Single Issuer**: ~1ms validation (fastest, no issuer lookup)
- **Static Multiple**: ~1ms validation (in-memory list check, very fast)
- **Dynamic Resolver**: ~1-5ms validation (with caching), ~10-20ms (cache miss with DB query)

**💡 Recommendation:** Start with `WithIssuer` or `WithIssuers` if possible. Only use `WithIssuersResolver` if you need dynamic tenant-based resolution.

#### Choosing the Right JWKS Provider

Use the correct JWKS provider based on your issuer validation approach:

| JWKS Provider | Use With | Why |
|---------------|----------|-----|
| **`CachingProvider`** | `WithIssuer` (single issuer) | Optimized for single issuer, simpler configuration |
| **`MultiIssuerProvider`** | `WithIssuers` or `WithIssuersResolver` | Handles dynamic JWKS routing per issuer, lazy loading |

**⚠️ Important:**
- Using `CachingProvider` with multiple issuers won't work correctly - it only caches JWKS for one issuer
- Using `MultiIssuerProvider` with a single issuer works but adds unnecessary overhead
- Always pair your issuer validation method with the appropriate provider

**Example Mismatch (❌ Don't do this):**
```go
// WRONG: CachingProvider can't handle multiple issuers
provider := jwks.NewCachingProvider(jwks.WithIssuerURL(url))
validator.New(
    validator.WithIssuers([]string{"issuer1", "issuer2"}), // Won't work!
    validator.WithKeyFunc(provider.KeyFunc),
)
```

**Correct Usage (✅ Do this):**
```go
// RIGHT: MultiIssuerProvider for multiple issuers
provider := jwks.NewMultiIssuerProvider()
validator.New(
    validator.WithIssuers([]string{"issuer1", "issuer2"}),
    validator.WithKeyFunc(provider.KeyFunc),
)
```

#### Static Multiple Issuers

Configure a fixed list of allowed issuers:

```go
// Use MultiIssuerProvider for automatic JWKS routing
provider, err := jwks.NewMultiIssuerProvider(
	jwks.WithMultiIssuerCacheTTL(5*time.Minute),
)

jwtValidator, err := validator.New(
	validator.WithKeyFunc(provider.KeyFunc),
	validator.WithAlgorithm(validator.RS256),
	validator.WithIssuers([]string{  // Multiple issuers!
		"https://tenant1.auth0.com/",
		"https://tenant2.auth0.com/",
		"https://tenant3.auth0.com/",
	}),
	validator.WithAudience("your-api-identifier"),
)
```

**Available Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `WithMultiIssuerCacheTTL` | JWKS cache refresh interval | 15 minutes |
| `WithMultiIssuerHTTPClient` | Custom HTTP client for JWKS fetching | 30s timeout |
| `WithMultiIssuerCache` | Custom cache implementation (e.g., Redis) | In-memory |
| `WithMaxProviders` | Maximum issuer providers to cache | 100 |

#### Large-Scale Multi-Tenant (100+ Tenants)

For applications with many tenants, use Redis and LRU eviction to manage memory:

```go
// Create Redis cache (see examples/http-multi-issuer-redis-example)
redisCache := &RedisCache{
	client: redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
	ttl:    5 * time.Minute,
}

// Configure provider with Redis and LRU eviction
provider, err := jwks.NewMultiIssuerProvider(
	jwks.WithMultiIssuerCacheTTL(5*time.Minute),
	jwks.WithMultiIssuerCache(redisCache),  // Share JWKS across instances
	jwks.WithMaxProviders(1000),            // Keep max 1000 providers in memory
)

jwtValidator, err := validator.New(
	validator.WithKeyFunc(provider.KeyFunc),
	validator.WithAlgorithm(validator.RS256),
	validator.WithIssuers(allowedIssuers),  // Your tenant list
	validator.WithAudience("your-api-identifier"),
)
```

**Why Redis for 100+ Tenants?**
- 📦 **Shared Cache**: JWKS data shared across multiple application instances
- 💾 **Memory Efficiency**: Offload JWKS storage from application memory
- 🔄 **Automatic Expiry**: Redis handles TTL and eviction
- 📈 **Scalability**: Handles thousands of tenants without memory bloat

#### Dynamic Issuer Resolution

Determine allowed issuers at request time based on context (tenant ID, database, etc.):

```go
// For many tenants, use Redis and limit cached providers
provider, err := jwks.NewMultiIssuerProvider(
	jwks.WithMultiIssuerCache(redisCache),  // Optional: Redis for JWKS caching
	jwks.WithMaxProviders(500),             // Optional: LRU limit for memory control
)

jwtValidator, err := validator.New(
	validator.WithKeyFunc(provider.KeyFunc),
	validator.WithAlgorithm(validator.RS256),
	validator.WithIssuersResolver(func(ctx context.Context) ([]string, error) {
		// Extract tenant from context (set by your middleware)
		tenantID, _ := ctx.Value("tenant").(string)

		// Check cache (user-managed caching for optimal performance)
		if cached, found := cache.Get(tenantID); found {
			return cached, nil
		}

		// Query database for tenant's allowed issuers
		issuers, err := database.GetIssuersForTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}

		// Cache for 5 minutes
		cache.Set(tenantID, issuers, 5*time.Minute)
		return issuers, nil
	}),
	validator.WithAudience("your-api-identifier"),
)
```

**Key Features:**
- 🔒 **Security**: Issuer validated BEFORE fetching JWKS (prevents SSRF attacks)
- ⚡ **Performance**: Per-issuer JWKS caching with lazy loading
- 🎯 **Flexibility**: User-controlled caching strategy (in-memory, Redis, etc.)
- 🔄 **Thread-Safe**: Concurrent request handling with double-checked locking

**Use Cases:**
- Multi-tenant SaaS applications
- Domain migration (support old and new domains simultaneously)
- Enterprise deployments with multiple Auth0 tenants
- Connected accounts from different identity providers

See the [multi-issuer examples](./examples/http-multi-issuer-example) for complete working code.

#### Security Requirements for Multiple Custom Domains (MCD)

When using `WithIssuers` or `WithIssuersResolver` to support Multiple Custom Domains (MCD), you are responsible for ensuring that only trusted issuer domains are returned.

Misconfiguring the issuer list or resolver is a critical security risk. It can cause the middleware to:
- Accept access tokens from unintended issuers
- Make discovery or JWKS requests to unintended domains

> **Note for Auth0 users:** The `WithIssuers` / `WithIssuersResolver` configuration for MCD is intended only for multiple custom domains that belong to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single API. Each domain in your issuer list should resolve to the same underlying Auth0 tenant.

**Dynamic Resolver Warning:**
If your `WithIssuersResolver` function uses request-derived values (such as headers, query parameters, or path segments), do not trust those values directly. Use them only to map known and expected request values to a fixed allowlist of issuer domains that you control.

In particular:
- Request headers like `Host`, `X-Forwarded-Host`, or `Origin` may be influenced by clients, proxies, or load balancers depending on your deployment setup
- The unverified `iss` claim from the token has not been signature-verified yet and must not be trusted by itself

If your deployment relies on reverse proxies or load balancers, ensure that host-related request information is treated as trusted only when it comes from trusted infrastructure. Misconfigured proxy handling can cause the middleware to trust unintended issuer domains.

**Example of a safe resolver pattern:**

The resolver receives `context.Context` with the unverified `iss` claim available via `validator.IssuerFromContext`. Use this only to check membership in a fixed allowlist, never as a trusted value for logging, database queries, or external calls.

```go
// allowedIssuers is a fixed set of trusted issuer URLs.
var allowedIssuers = map[string]bool{
    "https://brand-a.auth.example.com/":    true,
    "https://brand-a-jp.auth.example.com/": true,
    "https://brand-b.auth.example.com/":    true,
}

validator.WithIssuersResolver(func(ctx context.Context) ([]string, error) {
    // Return the full allowlist. The middleware will check the token's
    // iss claim against this list before making any JWKS requests.
    issuers := make([]string, 0, len(allowedIssuers))
    for iss := range allowedIssuers {
        issuers = append(issuers, iss)
    }
    return issuers, nil
})
```

The resolver's `context.Context` does not automatically include HTTP request information. If your resolver needs request-derived values (such as the host or tenant ID), an upstream middleware must explicitly set them in the context before the JWT middleware runs. Without that, the context will only contain the unverified `iss` claim via `validator.IssuerFromContext`.

For per-request filtering (e.g., tenant-scoped resolution), use trusted context values set by upstream middleware:

```go
validator.WithIssuersResolver(func(ctx context.Context) ([]string, error) {
    // tenantID must be set by a trusted upstream middleware,
    // not derived from the token or untrusted request headers.
    tenantID, ok := ctx.Value(tenantContextKey).(string)
    if !ok {
        return nil, fmt.Errorf("missing tenant in context")
    }

    switch tenantID {
    case "brand-a":
        return []string{
            "https://brand-a.auth.example.com/",
            "https://brand-a-jp.auth.example.com/",
        }, nil
    case "brand-b":
        return []string{
            "https://brand-b.auth.example.com/",
        }, nil
    default:
        return nil, fmt.Errorf("unknown tenant: %s", tenantID)
    }
})
```

## Examples

For complete working examples, check the [examples](./examples) directory:

- **[http-example](./examples/http-example)** - Basic HTTP server with HMAC
- **[http-jwks-example](./examples/http-jwks-example)** - Production setup with JWKS and Auth0
- **[http-multi-issuer-example](./examples/http-multi-issuer-example)** - Multiple issuers with static list
- **[http-multi-issuer-redis-example](./examples/http-multi-issuer-redis-example)** - Multi-tenant with Redis cache and LRU eviction
- **[http-dynamic-issuer-example](./examples/http-dynamic-issuer-example)** - Dynamic issuer resolution with caching
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

### Symmetric vs Asymmetric: When to Use What

Choose the right algorithm type based on your use case:

| Algorithm Type | Key Distribution | When to Use | Example Use Case |
|----------------|------------------|-------------|------------------|
| **Symmetric (HMAC)** | Shared secret between issuer and API | - Simple single-service architecture<br>- You control both token creation and validation<br>- Internal microservices communication | Backend API validating its own tokens |
| **Asymmetric (RS256, ES256, EdDSA)** | Public/private key pair (issuer has private, API has public) | - **Production with Auth0 or external OAuth providers**<br>- Multiple services validating tokens<br>- You don't control token creation<br>- Security-critical applications | Production API with Auth0, Okta, or any OAuth provider |

**🔐 Security Recommendations:**

1. **For Production with Auth0/OAuth providers: Use RS256** (default)
   - Industry standard for OAuth 2.0 and OpenID Connect
   - Auth0 uses RS256 by default
   - Public key rotation supported via JWKS
   - No shared secrets to manage

2. **For Modern Applications: Consider EdDSA**
   - Fastest signing and verification
   - Smaller signatures (better bandwidth)
   - Immune to timing attacks
   - Supported by Auth0 (must enable in dashboard)

3. **For Internal Services Only: HMAC is acceptable**
   - Simplest to configure (just a shared secret)
   - Fast performance
   - ⚠️ But: Secret must be protected and distributed securely

4. **Avoid using HMAC with external identity providers**
   - Can't use with Auth0/Okta (they use asymmetric keys)
   - Shared secret is a security risk at scale

**Example Configurations:**

Production with Auth0 (RS256):
```go
provider, _ := jwks.NewCachingProvider(jwks.WithIssuerURL(issuerURL))
validator.New(
    validator.WithKeyFunc(provider.KeyFunc),
    validator.WithAlgorithm(validator.RS256), // Standard for OAuth
    validator.WithIssuer(issuerURL.String()),
    validator.WithAudience("your-api"),
)
```

Internal microservices (HMAC):
```go
validator.New(
    validator.WithKeyFunc(func(ctx context.Context) (any, error) {
        return []byte(os.Getenv("JWT_SECRET")), nil
    }),
    validator.WithAlgorithm(validator.HS256), // Simple shared secret
    validator.WithIssuer("internal-service"),
    validator.WithAudience("my-api"),
)
```

High-security applications (EdDSA):
```go
provider, _ := jwks.NewCachingProvider(jwks.WithIssuerURL(issuerURL))
validator.New(
    validator.WithKeyFunc(provider.KeyFunc),
    validator.WithAlgorithm(validator.EdDSA), // Modern, fast, secure
    validator.WithIssuer(issuerURL.String()),
    validator.WithAudience("your-api"),
)
```

## Migration from v2

See [MIGRATION_GUIDE.md](./MIGRATION_GUIDE.md) for a complete guide on upgrading from v2 to v3.

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
