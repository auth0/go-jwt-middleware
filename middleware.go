package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

// JWTMiddleware is a middleware that validates JWTs and makes claims available in the request context.
// It wraps the core validation engine and provides HTTP-specific functionality like token extraction
// and error handling.
//
// Claims are stored in the context using core.SetClaims() and can be retrieved using core.GetClaims[T]().
type JWTMiddleware struct {
	core                *core.Core
	errorHandler        ErrorHandler
	tokenExtractor      TokenExtractor
	validateOnOptions   bool
	exclusionURLHandler ExclusionURLHandler
	logger              Logger

	// DPoP support
	dpopHeaderExtractor func(*http.Request) (string, error)
	trustedProxies      *TrustedProxyConfig

	// Temporary fields used during construction
	validator           *validator.Validator
	credentialsOptional bool
	dpopMode            *core.DPoPMode
	dpopProofOffset     *time.Duration
	dpopIATLeeway       *time.Duration
}

// Logger defines an optional logging interface compatible with log/slog.
// This is the same interface used by core for consistent logging across the stack.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// ExclusionURLHandler is a function that takes in a http.Request and returns
// true if the request should be excluded from JWT validation.
type ExclusionURLHandler func(r *http.Request) bool

// New constructs a new JWTMiddleware instance with the supplied options.
// All parameters are passed via options (pure options pattern).
//
// Required options:
//   - WithValidator: A configured validator instance
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
	if m.validator == nil {
		return ErrValidatorNil
	}
	return nil
}

// createCore creates the core.Core instance with the configured options
func (m *JWTMiddleware) createCore() error {
	// Wrap validator in adapter that implements core.Validator interface
	adapter := &validatorAdapter{validator: m.validator}

	// Build core options
	coreOpts := []core.Option{
		core.WithValidator(adapter),
		core.WithCredentialsOptional(m.credentialsOptional),
	}

	// Add logger if configured
	if m.logger != nil {
		coreOpts = append(coreOpts, core.WithLogger(m.logger))
	}

	// Add DPoP mode options
	if m.dpopMode != nil {
		coreOpts = append(coreOpts, core.WithDPoPMode(*m.dpopMode))
	}
	if m.dpopProofOffset != nil {
		coreOpts = append(coreOpts, core.WithDPoPProofOffset(*m.dpopProofOffset))
	}
	if m.dpopIATLeeway != nil {
		coreOpts = append(coreOpts, core.WithDPoPIATLeeway(*m.dpopIATLeeway))
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
	if m.dpopHeaderExtractor == nil {
		m.dpopHeaderExtractor = DPoPHeaderExtractor
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

// shouldSkipValidation checks if JWT validation should be skipped for this request.
func (m *JWTMiddleware) shouldSkipValidation(r *http.Request) bool {
	// Check exclusion handler
	if m.exclusionURLHandler != nil && m.exclusionURLHandler(r) {
		if m.logger != nil {
			m.logger.Debug("skipping JWT validation for excluded URL",
				"method", r.Method,
				"path", r.URL.Path)
		}
		return true
	}

	// Check OPTIONS method
	if !m.validateOnOptions && r.Method == http.MethodOptions {
		if m.logger != nil {
			m.logger.Debug("skipping JWT validation for OPTIONS request")
		}
		return true
	}

	return false
}

// validateToken performs JWT validation with or without DPoP support.
func (m *JWTMiddleware) validateToken(r *http.Request, token string) (any, *core.DPoPContext, error) {
	// Extract DPoP proof header (will be empty string if header not present)
	dpopProof, err := m.dpopHeaderExtractor(r)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to extract DPoP proof from request",
				"error", err,
				"method", r.Method,
				"path", r.URL.Path)
		}
		// Wrap in ValidationError for proper error handling
		validationErr := core.NewValidationError(
			core.ErrorCodeDPoPProofInvalid,
			fmt.Sprintf("Failed to extract DPoP proof: %s", err.Error()),
			err,
		)
		return nil, nil, validationErr
	}

	// Build full request URL for HTU validation using secure reconstruction
	requestURL := reconstructRequestURL(r, m.trustedProxies)

	// Validate token with DPoP support (handles both Bearer and DPoP tokens)
	// The core will handle DPoP mode (Allowed/Required/Disabled) logic
	return m.core.CheckTokenWithDPoP(
		r.Context(),
		token,
		dpopProof,
		r.Method,
		requestURL,
	)
}

// CheckJWT is the main JWTMiddleware function which performs the main logic. It
// is passed a http.Handler which will be called if the JWT passes validation.
func (m *JWTMiddleware) CheckJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip validation if excluded
		if m.shouldSkipValidation(r) {
			next.ServeHTTP(w, r)
			return
		}

		if m.logger != nil {
			m.logger.Debug("extracting JWT from request",
				"method", r.Method,
				"path", r.URL.Path)
		}

		// Extract token
		token, err := m.tokenExtractor(r)
		if err != nil {
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

		// Validate token (with or without DPoP)
		validToken, dpopCtx, err := m.validateToken(r, token)
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
		// core methods return (nil, nil, nil), so we continue without setting claims
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
			if dpopCtx != nil {
				m.logger.Debug("JWT validation successful (DPoP), setting claims and DPoP context in context",
					"jkt", dpopCtx.PublicKeyThumbprint)
			} else {
				m.logger.Debug("JWT validation successful (Bearer), setting claims in context")
			}
		}

		ctx := core.SetClaims(r.Context(), validToken)
		if dpopCtx != nil {
			ctx = core.SetDPoPContext(ctx, dpopCtx)
		}
		r = r.Clone(ctx)
		next.ServeHTTP(w, r)
	})
}
