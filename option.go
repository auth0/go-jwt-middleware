package jwtmiddleware

import (
	"context"
	"errors"
	"net/http"
)

// Option configures the JWTMiddleware.
// Returns error for validation failures.
type Option func(*JWTMiddleware) error

// validatorAdapter adapts the ValidateToken function to the core.TokenValidator interface
type validatorAdapter struct {
	validateFunc ValidateToken
}

func (v *validatorAdapter) ValidateToken(ctx context.Context, token string) (any, error) {
	return v.validateFunc(ctx, token)
}

// WithValidateToken sets the function to validate tokens (REQUIRED).
func WithValidateToken(validateToken ValidateToken) Option {
	return func(m *JWTMiddleware) error {
		if validateToken == nil {
			return ErrValidateTokenNil
		}
		m.validateToken = validateToken
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

// Sentinel errors for configuration validation
var (
	ErrValidateTokenNil   = errors.New("validateToken cannot be nil (use WithValidateToken)")
	ErrErrorHandlerNil    = errors.New("errorHandler cannot be nil")
	ErrTokenExtractorNil  = errors.New("tokenExtractor cannot be nil")
	ErrExclusionUrlsEmpty = errors.New("exclusion URLs list cannot be empty")
	ErrLoggerNil          = errors.New("logger cannot be nil")
)
