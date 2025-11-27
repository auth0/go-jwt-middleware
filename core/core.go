// Package core provides framework-agnostic JWT validation logic that can be used
// across different transport layers (HTTP, gRPC, etc.).
//
// The Core type encapsulates the validation logic and can be wrapped by transport-specific
// adapters to provide JWT middleware functionality for various frameworks.
package core

import (
	"context"
	"time"
)

// Validator defines the interface for JWT and DPoP validation.
// Implementations should validate tokens and DPoP proofs, returning the validated claims.
type Validator interface {
	ValidateToken(ctx context.Context, token string) (any, error)
	ValidateDPoPProof(ctx context.Context, proofString string) (DPoPProofClaims, error)
}

// Logger defines an optional logging interface for the core middleware.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Core is the framework-agnostic JWT validation engine.
// It contains the core logic for token validation without any dependency
// on specific transport protocols (HTTP, gRPC, etc.).
type Core struct {
	validator           Validator
	credentialsOptional bool
	logger              Logger

	// DPoP fields
	dpopMode        DPoPMode
	dpopProofOffset time.Duration
	dpopIATLeeway   time.Duration
}

// CheckToken validates a JWT token string and returns the validated claims.
//
// This is the core validation logic that is framework-agnostic:
//   - If token is empty and credentialsOptional is true, returns (nil, nil)
//   - If token is empty and credentialsOptional is false, returns ErrJWTMissing
//   - Otherwise, validates the token using the configured validator
//
// The returned claims (any) should be type-asserted by the caller
// to the expected claims type (typically *validator.ValidatedClaims).
func (c *Core) CheckToken(ctx context.Context, token string) (any, error) {
	// Handle empty token case
	if token == "" {
		if c.credentialsOptional {
			if c.logger != nil {
				c.logger.Debug("No token provided, but credentials are optional")
			}
			return nil, nil
		}

		if c.logger != nil {
			c.logger.Warn("No token provided and credentials are required")
		}

		return nil, ErrJWTMissing
	}

	// Validate token
	start := time.Now()
	claims, err := c.validator.ValidateToken(ctx, token)
	duration := time.Since(start)

	if err != nil {
		if c.logger != nil {
			c.logger.Error("Token validation failed", "error", err, "duration", duration)
		}

		return nil, err
	}

	// Success
	if c.logger != nil {
		c.logger.Debug("Token validated successfully", "duration", duration)
	}

	return claims, nil
}
