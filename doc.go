/*
Package jwtmiddleware provides HTTP middleware for JWT authentication.

This package implements JWT authentication middleware for standard Go net/http
servers. It validates JWTs, extracts claims, and makes them available in the
request context. The middleware follows the Core-Adapter pattern, with this
package serving as the HTTP transport adapter.

# Quick Start

	import (
	    "github.com/auth0/go-jwt-middleware/v3"
	    "github.com/auth0/go-jwt-middleware/v3/jwks"
	    "github.com/auth0/go-jwt-middleware/v3/validator"
	)

	func main() {
	    // Create JWKS provider
	    issuerURL, _ := url.Parse("https://your-domain.auth0.com/")
	    provider, err := jwks.NewCachingProvider(
	        jwks.WithIssuerURL(issuerURL),
	    )
	    if err != nil {
	        log.Fatal(err)
	    }

	    // Create validator
	    jwtValidator, err := validator.New(
	        validator.WithKeyFunc(provider.KeyFunc),
	        validator.WithAlgorithm(validator.RS256),
	        validator.WithIssuer(issuerURL.String()),
	        validator.WithAudience("your-api-identifier"),
	    )
	    if err != nil {
	        log.Fatal(err)
	    }

	// Create middleware
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
	)
	if err != nil {
		log.Fatal(err)
	}	    // Use with your HTTP server
	    http.Handle("/api/", middleware.CheckJWT(apiHandler))
	    http.ListenAndServe(":8080", nil)
	}

# Accessing Claims

Use the type-safe generic helpers to access claims in your handlers:

	func apiHandler(w http.ResponseWriter, r *http.Request) {
	    // Type-safe claims retrieval
	    claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	    if err != nil {
	        http.Error(w, "Unauthorized", http.StatusUnauthorized)
	        return
	    }

	    // Access claims
	    fmt.Fprintf(w, "Hello, %s!", claims.RegisteredClaims.Subject)
	}

Alternative: Check if claims exist without retrieving them:

	if jwtmiddleware.HasClaims(r.Context()) {
	    // Claims are present
	}

v2 compatibility (type assertion):

	claimsValue := r.Context().Value(jwtmiddleware.ContextKey{})
	if claimsValue == nil {
	    // No claims
	}
	claims := claimsValue.(*validator.ValidatedClaims)

# Configuration Options

All configuration is done through functional options:

Required:
  - WithValidator: A configured validator instance

Optional:
  - WithCredentialsOptional: Allow requests without JWT
  - WithValidateOnOptions: Validate JWT on OPTIONS requests
  - WithErrorHandler: Custom error response handler
  - WithTokenExtractor: Custom token extraction logic
  - WithExclusionUrls: URLs to skip JWT validation
  - WithLogger: Structured logging (compatible with log/slog)

# Optional Credentials

Allow requests without JWT (useful for public + authenticated endpoints):

	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
		jwtmiddleware.WithCredentialsOptional(true),
	)	func handler(w http.ResponseWriter, r *http.Request) {
	    claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	    if err != nil {
	        // No JWT provided - serve public content
	        fmt.Fprintln(w, "Public content")
	        return
	    }
	    // JWT provided - serve authenticated content
	    fmt.Fprintf(w, "Hello, %s!", claims.RegisteredClaims.Subject)
	}

# Custom Error Handling

Implement custom error responses:

	func myErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	    log.Printf("JWT error: %v", err)

	    // Check error type
	    if errors.Is(err, jwtmiddleware.ErrJWTMissing) {
	        http.Error(w, "No token provided", http.StatusUnauthorized)
	        return
	    }

	    // Check for ValidationError
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
		jwtmiddleware.WithErrorHandler(myErrorHandler),
	)# Token Extraction

Default: Authorization header with Bearer scheme

	Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

Custom extractors:

From Cookie:

	extractor := jwtmiddleware.CookieTokenExtractor("jwt")

From Query Parameter:

	extractor := jwtmiddleware.ParameterTokenExtractor("token")

Multiple Sources (tries in order):

	extractor := jwtmiddleware.MultiTokenExtractor(
	    jwtmiddleware.AuthHeaderTokenExtractor,
	    jwtmiddleware.CookieTokenExtractor("jwt"),
	)

Use with middleware:

	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
		jwtmiddleware.WithTokenExtractor(extractor),
	)# URL Exclusions

Skip JWT validation for specific URLs:

	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
		jwtmiddleware.WithExclusionUrls([]string{
		"/health",
		"/metrics",
		"/public",
	}),
	)# Logging

Enable structured logging (compatible with log/slog):

		import "log/slog"

		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

		middleware, err := jwtmiddleware.New(
			jwtmiddleware.WithValidator(jwtValidator),
			jwtmiddleware.WithLogger(logger),
		)Logs will include:
	  - Token extraction attempts
	  - Validation success/failure with timing
	  - Excluded URLs
	  - OPTIONS request handling

# Error Responses

The DefaultErrorHandler provides RFC 6750 compliant error responses:

401 Unauthorized (missing token):

	{
	    "error": "invalid_request",
	    "error_description": "Authorization header required"
	}
	WWW-Authenticate: Bearer realm="api"

401 Unauthorized (invalid token):

	{
	    "error": "invalid_token",
	    "error_description": "Token has expired",
	    "error_code": "token_expired"
	}
	WWW-Authenticate: Bearer error="invalid_token", error_description="Token has expired"

400 Bad Request (extraction error):

	{
	    "error": "invalid_request",
	    "error_description": "Authorization header format must be Bearer {token}"
	}

# Context Key

v3 uses an unexported context key for collision-free claims storage:

	type contextKey int

This prevents conflicts with other packages. Always use the provided
helper functions (GetClaims, HasClaims, SetClaims) to access claims.

v2 compatibility: The exported ContextKey{} struct is still available:

	claimsValue := r.Context().Value(jwtmiddleware.ContextKey{})

However, the generic helpers are recommended for type safety.

# Custom Claims

Define and use custom claims in your handlers:

	type MyCustomClaims struct {
	    Scope       string   `json:"scope"`
	    Permissions []string `json:"permissions"`
	}

	func (c *MyCustomClaims) Validate(ctx context.Context) error {
	    if c.Scope == "" {
	        return errors.New("scope is required")
	    }
	    return nil
	}

Configure validator with custom claims:

	jwtValidator, err := validator.New(
	    validator.WithKeyFunc(provider.KeyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer(issuerURL.String()),
	    validator.WithAudience("your-api-identifier"),
	    validator.WithCustomClaims(func() *MyCustomClaims {
	        return &MyCustomClaims{}
	    }),
	)

Access in handlers:

	func handler(w http.ResponseWriter, r *http.Request) {
	    claims, _ := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	    customClaims := claims.CustomClaims.(*MyCustomClaims)

	    if contains(customClaims.Permissions, "read:data") {
	        // User has permission
	    }
	}

# Thread Safety

The JWTMiddleware instance is immutable after creation and safe for
concurrent use. The same middleware can be used across multiple routes
and handle concurrent requests.

# Performance

Typical request overhead with JWKS caching:
  - Token extraction: <0.1ms
  - Signature verification: <1ms (cached keys)
  - Claims validation: <0.1ms
  - Total: <2ms per request

First request (cold cache):
  - OIDC discovery: ~100-300ms
  - JWKS fetch: ~50-200ms
  - Validation: <1ms
  - Total: ~150-500ms

# Architecture

This package is the HTTP adapter in the Core-Adapter pattern:

	┌─────────────────────────────────────────────┐
	│         HTTP Middleware (THIS PACKAGE)      │
	│  - Token extraction from HTTP requests      │
	│  - Error responses (401, 400)               │
	│  - Context integration                      │
	└────────────────┬────────────────────────────┘
	                 │
	                 ▼
	┌─────────────────────────────────────────────┐
	│          Core Engine                        │
	│  (Framework-Agnostic Validation Logic)      │
	└────────────────┬────────────────────────────┘
	                 │
	                 ▼
	┌─────────────────────────────────────────────┐
	│          Validator                          │
	│  (JWT Parsing & Verification)               │
	└─────────────────────────────────────────────┘

This design allows the same validation logic to be used with different
transports (HTTP, gRPC, WebSocket, etc.) without code duplication.

# Migration from v2

Key changes from v2 to v3:

1. Options Pattern: All configuration via functional options

	// v2
	jwtmiddleware.New(validator.New, options...)

	// v3
	jwtmiddleware.New(
		jwtmiddleware.WithValidator(validator),
		jwtmiddleware.WithCredentialsOptional(false),
	)2. Generic Claims Retrieval: Type-safe with generics

	// v2
	claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)

	// v3
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())

3. Validator Options: Pure options pattern

	// v2
	validator.New(keyFunc, alg, issuer, audience, opts...)

	// v3
	validator.New(
	    validator.WithKeyFunc(keyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer(issuer),
	    validator.WithAudience(audience),
	)

4. JWKS Provider: Pure options pattern

	// v2
	jwks.NewProvider(issuerURL, options...)

	// v3
	jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	    jwks.WithCacheTTL(15*time.Minute),
	)

5. ExclusionUrlHandler → ExclusionURLHandler: Proper URL capitalization

See MIGRATION.md for a complete guide.
*/
package jwtmiddleware
