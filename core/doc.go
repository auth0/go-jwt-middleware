/*
Package core provides framework-agnostic JWT validation logic that can be used
across different transport layers (HTTP, gRPC, etc.).

The Core type encapsulates the validation logic without dependencies on any
specific transport protocol. This allows the same validation code to be reused
across multiple frameworks and transports.

# Architecture

The core package implements the "Core" in the Core-Adapter pattern:

	┌─────────────────────────────────────────────┐
	│         Transport Adapters                  │
	│  (HTTP, gRPC, Gin, Echo - Framework Specific)│
	└────────────────┬────────────────────────────┘
	                 │
	                 ▼
	┌─────────────────────────────────────────────┐
	│          Core Engine (THIS PACKAGE)         │
	│  (Framework-Agnostic Validation Logic)      │
	│  • Token Validation                         │
	│  • Credentials Optional Logic               │
	│  • Logger Integration                       │
	└────────────────┬────────────────────────────┘
	                 │
	                 ▼
	┌─────────────────────────────────────────────┐
	│          Validator                          │
	│  (JWT Parsing & Verification)               │
	└─────────────────────────────────────────────┘

# Basic Usage

Create a Core instance with a validator and options:

	import (
	    "github.com/auth0/go-jwt-middleware/v3/core"
	    "github.com/auth0/go-jwt-middleware/v3/validator"
	)

	// Create validator
	val, err := validator.New(
	    validator.WithKeyFunc(keyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer("https://issuer.example.com/"),
	    validator.WithAudience("my-api"),
	)
	if err != nil {
	    log.Fatal(err)
	}

	// Create core with validator
	c, err := core.New(
	    core.WithValidator(val),
	    core.WithCredentialsOptional(false),
	)
	if err != nil {
	    log.Fatal(err)
	}

	// Validate token
	claims, err := c.CheckToken(ctx, tokenString)
	if err != nil {
	    // Handle validation error
	}

# Type-Safe Context Helpers

The package provides generic context helpers for type-safe claims retrieval:

	// Store claims in context
	ctx = core.SetClaims(ctx, claims)

	// Retrieve claims with type safety
	claims, err := core.GetClaims[*validator.ValidatedClaims](ctx)
	if err != nil {
	    // Claims not found
	}

	// Check if claims exist
	if core.HasClaims(ctx) {
	    // Claims are present
	}

# Error Handling

The package provides structured error handling with ValidationError:

	claims, err := c.CheckToken(ctx, tokenString)
	if err != nil {
	    // Check for sentinel errors
	    if errors.Is(err, core.ErrJWTMissing) {
	        // Token missing
	    }
	    if errors.Is(err, core.ErrJWTInvalid) {
	        // Token invalid
	    }

	    // Check for ValidationError with error codes
	    var validationErr *core.ValidationError
	    if errors.As(err, &validationErr) {
	        switch validationErr.Code {
	        case core.ErrorCodeTokenExpired:
	            // Handle expired token
	        case core.ErrorCodeInvalidSignature:
	            // Handle signature error
	        }
	    }
	}

# Logging

Optional logging can be configured to debug the validation flow:

	c, err := core.New(
	    core.WithValidator(val),
	    core.WithLogger(logger), // slog.Logger or compatible
	)

The logger will output:
  - Token validation attempts
  - Success/failure with duration
  - Credentials optional behavior

# Context Keys

The package uses an unexported context key type to prevent collisions:

	type contextKey int

This ensures that claims stored by this package cannot accidentally
conflict with other context values in your application.
*/
package core
