package jwtmiddleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v3/validator"
)

// Option configures the JWTMiddleware.
// Returns error for validation failures.
type Option func(*JWTMiddleware) error

// TokenValidator defines the interface for token validation.
// This interface is satisfied by *validator.Validator and allows
// explicit passing of validation methods.
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (any, error)
}

// validatorAdapter adapts the TokenValidator to the core.TokenValidator interface
type validatorAdapter struct {
	validator TokenValidator
}

func (v *validatorAdapter) ValidateToken(ctx context.Context, token string) (any, error) {
	return v.validator.ValidateToken(ctx, token)
}

// WithValidator sets the validator instance to validate tokens (REQUIRED).
// The validator must be a *validator.Validator instance.
// This approach allows explicit passing of validation methods and future
// extensibility for methods like ValidateDPoP.
//
// Example:
//
//	v, err := validator.New(
//	    validator.WithKeyFunc(keyFunc),
//	    validator.WithAlgorithm(validator.RS256),
//	    validator.WithIssuer("https://issuer.example.com/"),
//	    validator.WithAudience("my-api"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidator(v),
//	)
func WithValidator(v *validator.Validator) Option {
	return func(m *JWTMiddleware) error {
		if v == nil {
			return ErrValidatorNil
		}
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
//	    jwtmiddleware.WithValidator(validator),
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

// Sentinel errors for configuration validation
var (
	ErrValidatorNil       = errors.New("validator cannot be nil (use WithValidator)")
	ErrErrorHandlerNil    = errors.New("errorHandler cannot be nil")
	ErrTokenExtractorNil  = errors.New("tokenExtractor cannot be nil")
	ErrExclusionUrlsEmpty = errors.New("exclusion URLs list cannot be empty")
	ErrLoggerNil          = errors.New("logger cannot be nil")
)
