package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v3/core"
)

type JWTMiddleware struct {
	core                *core.Core
	errorHandler        ErrorHandler
	tokenExtractor      TokenExtractor
	validateOnOptions   bool
	exclusionUrlHandler ExclusionUrlHandler
	logger              Logger

	// Temporary fields used during construction
	validateToken       ValidateToken
	credentialsOptional bool
}

// Logger defines an optional logging interface compatible with log/slog.
// This is the same interface used by core for consistent logging across the stack.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// ValidateToken takes in a string JWT and makes sure it is valid and
// returns the valid token. If it is not valid it will return nil and
// an error message describing why validation failed.
// Inside ValidateToken things like key and alg checking can happen.
// In the default implementation we can add safe defaults for those.
type ValidateToken func(context.Context, string) (any, error)

// ExclusionUrlHandler is a function that takes in a http.Request and returns
// true if the request should be excluded from JWT validation.
type ExclusionUrlHandler func(r *http.Request) bool

// New constructs a new JWTMiddleware instance with the supplied options.
// All parameters are passed via options (pure options pattern).
//
// Example:
//
//	middleware, err := jwtmiddleware.New(
//	    jwtmiddleware.WithValidateToken(validator.ValidateToken),
//	    jwtmiddleware.WithCredentialsOptional(false),
//	)
//	if err != nil {
//	    log.Fatalf("failed to create middleware: %v", err)
//	}
func New(opts ...Option) (*JWTMiddleware, error) {
	m := &JWTMiddleware{
		// Set secure defaults before applying options
		validateOnOptions:   true,  // Validate OPTIONS by default
		credentialsOptional: false, // Credentials required by default
	}

	// Apply all options
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Validate required configuration
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("invalid middleware configuration: %w", err)
	}

	// Apply defaults for optional fields not set by options
	m.applyDefaults()

	// Create the core with the configured validator and options
	if err := m.createCore(); err != nil {
		return nil, fmt.Errorf("failed to create core: %w", err)
	}

	return m, nil
}

// validate ensures all required fields are set
func (m *JWTMiddleware) validate() error {
	if m.validateToken == nil {
		return ErrValidateTokenNil
	}
	return nil
}

// createCore creates the core.Core instance with the configured options
func (m *JWTMiddleware) createCore() error {
	adapter := &validatorAdapter{validateFunc: m.validateToken}

	// Build core options
	coreOpts := []core.Option{
		core.WithValidator(adapter),
		core.WithCredentialsOptional(m.credentialsOptional),
	}

	// Add logger if configured
	if m.logger != nil {
		coreOpts = append(coreOpts, core.WithLogger(m.logger))
	}

	coreInstance, err := core.New(coreOpts...)
	if err != nil {
		return err
	}
	m.core = coreInstance
	return nil
}

// applyDefaults sets secure default values for optional fields
func (m *JWTMiddleware) applyDefaults() {
	if m.errorHandler == nil {
		m.errorHandler = DefaultErrorHandler
	}
	if m.tokenExtractor == nil {
		m.tokenExtractor = AuthHeaderTokenExtractor
	}
}

// GetClaims retrieves claims from the context with type safety using generics.
// This provides compile-time type checking and eliminates the need for manual type assertions.
//
// Example:
//
//	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
//	if err != nil {
//	    http.Error(w, "failed to get claims", http.StatusInternalServerError)
//	    return
//	}
//	fmt.Println(claims.RegisteredClaims.Subject)
func GetClaims[T any](ctx context.Context) (T, error) {
	return core.GetClaims[T](ctx)
}

// MustGetClaims retrieves claims from the context or panics.
// Use only when you are certain claims exist (e.g., after middleware has run).
//
// Example:
//
//	claims := jwtmiddleware.MustGetClaims[*validator.ValidatedClaims](r.Context())
//	fmt.Println(claims.RegisteredClaims.Subject)
func MustGetClaims[T any](ctx context.Context) T {
	claims, err := core.GetClaims[T](ctx)
	if err != nil {
		panic(err)
	}
	return claims
}

// HasClaims checks if claims exist in the context.
//
// Example:
//
//	if jwtmiddleware.HasClaims(r.Context()) {
//	    claims, _ := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
//	    // Use claims...
//	}
func HasClaims(ctx context.Context) bool {
	return core.HasClaims(ctx)
}

// CheckJWT is the main JWTMiddleware function which performs the main logic. It
// is passed a http.Handler which will be called if the JWT passes validation.
func (m *JWTMiddleware) CheckJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If there's an exclusion handler and the URL matches, skip JWT validation
		if m.exclusionUrlHandler != nil && m.exclusionUrlHandler(r) {
			if m.logger != nil {
				m.logger.Debug("skipping JWT validation for excluded URL",
					"method", r.Method,
					"path", r.URL.Path)
			}
			next.ServeHTTP(w, r)
			return
		}
		// If we don't validate on OPTIONS and this is OPTIONS
		// then continue onto next without validating.
		if !m.validateOnOptions && r.Method == http.MethodOptions {
			if m.logger != nil {
				m.logger.Debug("skipping JWT validation for OPTIONS request")
			}
			next.ServeHTTP(w, r)
			return
		}

		if m.logger != nil {
			m.logger.Debug("extracting JWT from request",
				"method", r.Method,
				"path", r.URL.Path)
		}

		token, err := m.tokenExtractor(r)
		if err != nil {
			// This is not ErrJWTMissing because an error here means that the
			// tokenExtractor had an error and _not_ that the token was missing.
			if m.logger != nil {
				m.logger.Error("failed to extract token from request",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path)
			}
			m.errorHandler(w, r, fmt.Errorf("error extracting token: %w", err))
			return
		}

		if m.logger != nil {
			m.logger.Debug("validating JWT")
		}

		// Validate the token using the core validator.
		// Core handles empty token logic based on credentialsOptional setting.
		validToken, err := m.core.CheckToken(r.Context(), token)
		if err != nil {
			if m.logger != nil {
				m.logger.Warn("JWT validation failed",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path)
			}
			m.errorHandler(w, r, &invalidError{details: err})
			return
		}

		// If credentials are optional and no token was provided,
		// core.CheckToken returns (nil, nil), so we continue without setting claims
		if validToken == nil {
			if m.logger != nil {
				m.logger.Debug("no credentials provided, continuing without claims (credentials optional)")
			}
			next.ServeHTTP(w, r)
			return
		}

		// No err means we have a valid token, so set
		// it into the context and continue onto next.
		if m.logger != nil {
			m.logger.Debug("JWT validation successful, setting claims in context")
		}
		r = r.Clone(core.SetClaims(r.Context(), validToken))
		next.ServeHTTP(w, r)
	})
}
