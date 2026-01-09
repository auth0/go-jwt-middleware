package jwtmiddleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

// Option configures the JWTMiddleware.
// Returns error for validation failures.
type Option func(*JWTMiddleware) error

// validatorAdapter adapts the validator.Validator to the core.Validator interface
type validatorAdapter struct {
	validator *validator.Validator
}

func (v *validatorAdapter) ValidateToken(ctx context.Context, token string) (any, error) {
	return v.validator.ValidateToken(ctx, token)
}

func (v *validatorAdapter) ValidateDPoPProof(ctx context.Context, proofString string) (core.DPoPProofClaims, error) {
	return v.validator.ValidateDPoPProof(ctx, proofString)
}

// WithValidator configures the middleware with a JWT validator.
// This is the REQUIRED way to configure the middleware.
//
// The validator must implement ValidateToken, and optionally ValidateDPoPProof
// for DPoP support. The Auth0 validator package provides both methods automatically.
//
// Example:
//
//	validator, _ := validator.New(...)  // Supports both JWT and DPoP
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	)
func WithValidator(v *validator.Validator) Option {
	return func(m *JWTMiddleware) error {
		if v == nil {
			return ErrValidatorNil
		}

		// Store the validator instance
		m.validator = v

		return nil
	}
}

// WithCredentialsOptional sets whether credentials are optional.
// If set to true, an empty token will be considered valid.
//
// Default: false (credentials required)
func WithCredentialsOptional(value bool) Option {
	return func(m *JWTMiddleware) error {
		m.credentialsOptional = value
		return nil
	}
}

// WithValidateOnOptions sets whether OPTIONS requests should have their JWT validated.
//
// Default: true (OPTIONS requests are validated)
func WithValidateOnOptions(value bool) Option {
	return func(m *JWTMiddleware) error {
		m.validateOnOptions = value
		return nil
	}
}

// WithErrorHandler sets the handler called when errors occur during JWT validation.
// See the ErrorHandler type for more information.
//
// Default: DefaultErrorHandler
func WithErrorHandler(h ErrorHandler) Option {
	return func(m *JWTMiddleware) error {
		if h == nil {
			return ErrErrorHandlerNil
		}
		m.errorHandler = h
		return nil
	}
}

// WithTokenExtractor sets the function to extract the JWT from the request.
//
// Default: AuthHeaderTokenExtractor
func WithTokenExtractor(e TokenExtractor) Option {
	return func(m *JWTMiddleware) error {
		if e == nil {
			return ErrTokenExtractorNil
		}
		m.tokenExtractor = e
		return nil
	}
}

// WithExclusionUrls configures URL patterns to exclude from JWT validation.
// URLs can be full URLs or just paths.
func WithExclusionUrls(exclusions []string) Option {
	return func(m *JWTMiddleware) error {
		if len(exclusions) == 0 {
			return ErrExclusionUrlsEmpty
		}
		m.exclusionURLHandler = func(r *http.Request) bool {
			requestFullURL := r.URL.String()
			requestPath := r.URL.Path

			for _, exclusion := range exclusions {
				if requestFullURL == exclusion || requestPath == exclusion {
					return true
				}
			}
			return false
		}
		return nil
	}
}

// WithLogger sets an optional logger for the middleware.
// The logger will be used throughout the validation flow in both middleware and core.
//
// The logger interface is compatible with log/slog.Logger and similar loggers.
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidateToken(validator.ValidateToken),
//	    jwtmiddleware.WithLogger(slog.Default()),
//	)
func WithLogger(logger Logger) Option {
	return func(m *JWTMiddleware) error {
		if logger == nil {
			return ErrLoggerNil
		}
		m.logger = logger
		return nil
	}
}

// WithDPoPHeaderExtractor sets a custom DPoP header extractor.
// Optional - defaults to extracting from the "DPoP" HTTP header per RFC 9449.
//
// Use this for non-standard scenarios:
//   - Custom header names (e.g., "X-DPoP-Proof")
//   - Header transformations (e.g., base64 decoding)
//   - Alternative sources (e.g., query parameters)
//   - Testing/mocking
//
// Example (custom header name):
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	    jwtmiddleware.WithDPoPHeaderExtractor(func(r *http.Request) (string, error) {
//	        return r.Header.Get("X-DPoP-Proof"), nil
//	    }),
//	)
func WithDPoPHeaderExtractor(extractor func(*http.Request) (string, error)) Option {
	return func(m *JWTMiddleware) error {
		if extractor == nil {
			return ErrDPoPHeaderExtractorNil
		}
		m.dpopHeaderExtractor = extractor
		return nil
	}
}

// WithDPoPMode sets the DPoP operational mode.
//
// Modes:
//   - core.DPoPAllowed (default): Accept both Bearer and DPoP tokens
//   - core.DPoPRequired: Only accept DPoP tokens, reject Bearer tokens
//   - core.DPoPDisabled: Only accept Bearer tokens, ignore DPoP headers
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	    jwtmiddleware.WithDPoPMode(core.DPoPRequired), // Require DPoP
//	)
func WithDPoPMode(mode core.DPoPMode) Option {
	return func(m *JWTMiddleware) error {
		m.dpopMode = &mode
		return nil
	}
}

// WithDPoPProofOffset sets the maximum age for DPoP proofs.
// This determines how far in the past a DPoP proof's iat timestamp can be.
//
// Default: 300 seconds (5 minutes)
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	    jwtmiddleware.WithDPoPProofOffset(60 * time.Second), // Stricter: 60s
//	)
func WithDPoPProofOffset(offset time.Duration) Option {
	return func(m *JWTMiddleware) error {
		if offset < 0 {
			return errors.New("DPoP proof offset cannot be negative")
		}
		m.dpopProofOffset = &offset
		return nil
	}
}

// WithDPoPIATLeeway sets the clock skew allowance for DPoP proof iat claims.
// This allows DPoP proofs with iat timestamps slightly in the future due to clock drift.
//
// Default: 5 seconds
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(validator),
//	    jwtmiddleware.WithDPoPIATLeeway(30 * time.Second), // More lenient: 30s
//	)
func WithDPoPIATLeeway(leeway time.Duration) Option {
	return func(m *JWTMiddleware) error {
		if leeway < 0 {
			return errors.New("DPoP IAT leeway cannot be negative")
		}
		m.dpopIATLeeway = &leeway
		return nil
	}
}

// Sentinel errors for configuration validation
var (
	ErrValidatorNil           = errors.New("validator cannot be nil (use WithValidator)")
	ErrErrorHandlerNil        = errors.New("errorHandler cannot be nil")
	ErrTokenExtractorNil      = errors.New("tokenExtractor cannot be nil")
	ErrExclusionUrlsEmpty     = errors.New("exclusion URLs list cannot be empty")
	ErrLoggerNil              = errors.New("logger cannot be nil")
	ErrDPoPHeaderExtractorNil = errors.New("DPoP header extractor cannot be nil")
)
