package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v2/validator"
)

// ContextKey is the key used in the request
// context where the information from a
// validated JWT will be stored.
type ContextKey struct{ Name string }

var DefaultClaimsKey = ContextKey{Name: "jwt"}

// JWTMiddleware provides a configurable JWT authentication middleware.
type JWTMiddleware struct {
	validateToken       ValidateToken
	errorHandler        ErrorHandler
	tokenExtractor      TokenExtractor
	credentialsOptional bool
	validateOnOptions   bool
	exclusionUrlHandler ExclusionUrlHandler
	contextKey          ContextKey
	logger              Logger
	logLevel            LogLevel
	tracer              Tracer
	metrics             Metrics
}

// ValidateToken takes in a string JWT and makes sure it is valid and
// returns the valid token. If it is not valid it will return nil and
// an error message describing why validation failed.
// Inside ValidateToken things like key and alg checking can happen.
// In the default implementation we can add safe defaults for those.
type ValidateToken func(context.Context, string) (interface{}, error)

// ExclusionUrlHandler is a function that takes in a http.Request and returns
// true if the request should be excluded from JWT validation.
type ExclusionUrlHandler func(r *http.Request) bool

// New constructs a new JWTMiddleware instance with the supplied options.
// It requires a ValidateToken function to be passed in, so it can
// properly validate tokens.
func New(validateToken ValidateToken, opts ...Option) *JWTMiddleware {
	m := &JWTMiddleware{
		validateToken:       validateToken,
		errorHandler:        DefaultErrorHandler,
		credentialsOptional: false,
		tokenExtractor:      AuthHeaderTokenExtractor,
		validateOnOptions:   true,
		tracer:              &NoopTracer{},
		metrics:             &NoopMetrics{},
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// CheckJWT is the main JWTMiddleware function which performs the main logic. It
// is passed a http.Handler which will be called if the JWT passes validation.
func (m *JWTMiddleware) CheckJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := m.tracer.StartSpan("jwtmiddleware.CheckJWT")
		defer span.Finish()
		m.metrics.IncCounter("jwtmiddleware.requests", map[string]string{"path": r.URL.Path, "method": r.Method})

		if m.logger != nil && m.logLevel >= LogLevelDebug {
			m.logger.Debugf("JWTMiddleware: Checking JWT for %s %s", r.Method, r.URL.Path)
		}
		if m.exclusionUrlHandler != nil && m.exclusionUrlHandler(r) {
			span.SetTag("excluded", true)
			m.metrics.IncCounter("jwtmiddleware.excluded", map[string]string{"path": r.URL.Path, "method": r.Method})

			if m.logger != nil && m.logLevel >= LogLevelInfo {
				m.logger.Infof("JWTMiddleware: Excluded URL %s", r.URL.Path)
			}
			next.ServeHTTP(w, r)
			return
		}
		if !m.validateOnOptions && r.Method == http.MethodOptions {
			span.SetTag("options_skipped", true)
			m.metrics.IncCounter("jwtmiddleware.options_skipped", map[string]string{"path": r.URL.Path, "method": r.Method})

			if m.logger != nil && m.logLevel >= LogLevelDebug {
				m.logger.Debugf("JWTMiddleware: Skipping JWT validation for OPTIONS request %s", r.URL.Path)
			}
			next.ServeHTTP(w, r)
			return
		}
		token, err := m.tokenExtractor(r)
		if err != nil {
			span.SetTag("token_extraction_error", true)
			m.metrics.IncCounter("jwtmiddleware.token_extraction_error", map[string]string{"path": r.URL.Path, "method": r.Method})

			if m.logger != nil && m.logLevel >= LogLevelError {
				m.logger.Errorf("JWTMiddleware: Error extracting token: %v", err)
			}
			// Use structured error
			extractErr := NewJWTError(ErrJWTInvalid, fmt.Sprintf("error extracting token: %v", err), err)
			m.errorHandler(w, r, extractErr)
			return
		}
		if token == "" {
			if m.credentialsOptional {
				span.SetTag("credentials_optional", true)
				m.metrics.IncCounter("jwtmiddleware.credentials_optional", map[string]string{"path": r.URL.Path, "method": r.Method})

				if m.logger != nil && m.logLevel >= LogLevelInfo {
					m.logger.Infof("JWTMiddleware: No token found, but credentials are optional for %s", r.URL.Path)
				}
				next.ServeHTTP(w, r)
				return
			}
			span.SetTag("missing_token", true)
			m.metrics.IncCounter("jwtmiddleware.missing_token", map[string]string{"path": r.URL.Path, "method": r.Method})

			if m.logger != nil && m.logLevel >= LogLevelWarn {
				m.logger.Warnf("JWTMiddleware: No token found and credentials are required for %s", r.URL.Path)
			}
			// Use structured error
			missingErr := NewJWTError(ErrJWTMissing, "", nil)
			m.errorHandler(w, r, missingErr)
			return
		}
		span.SetTag("token_found", true)
		m.metrics.IncCounter("jwtmiddleware.token_found", map[string]string{"path": r.URL.Path, "method": r.Method})

		if m.logger != nil && m.logLevel >= LogLevelDebug {
			m.logger.Debugf("JWTMiddleware: Validating token for %s", r.URL.Path)
		}
		validToken, err := m.validateToken(r.Context(), token)
		if err != nil {
			span.SetTag("token_validation_error", true)
			m.metrics.IncCounter("jwtmiddleware.token_validation_error", map[string]string{"path": r.URL.Path, "method": r.Method})

			if m.logger != nil && m.logLevel >= LogLevelError {
				m.logger.Errorf("JWTMiddleware: Token validation failed: %v", err)
			}
			// Use structured error
			validationErr := NewJWTError(ErrJWTInvalid, err.Error(), err)
			m.errorHandler(w, r, validationErr)
			return
		}
		span.SetTag("token_validated", true)
		m.metrics.IncCounter("jwtmiddleware.token_validated", map[string]string{"path": r.URL.Path, "method": r.Method})

		if m.logger != nil && m.logLevel >= LogLevelInfo {
			m.logger.Infof("JWTMiddleware: Token validated successfully for %s", r.URL.Path)
		}
		key := m.contextKey
		if key == (ContextKey{}) {
			key = DefaultClaimsKey
		}
		r = r.Clone(context.WithValue(r.Context(), key, validToken))
		next.ServeHTTP(w, r)
	})
}

// Logger returns the configured logger, or nil if none is set.
func (m *JWTMiddleware) Logger() Logger {
	return m.logger
}

// LogLevel returns the configured log level.
func (m *JWTMiddleware) LogLevel() LogLevel {
	return m.logLevel
}

// GetContextKey returns the configured context key for claims, or the default key if not set.
func (m *JWTMiddleware) GetContextKey() ContextKey {
	if m.contextKey == (ContextKey{}) {
		return DefaultClaimsKey
	}
	return m.contextKey
}

// Tracer returns the configured tracer, or NoopTracer if none is set.
func (m *JWTMiddleware) Tracer() Tracer {
	if m.tracer == nil {
		return &NoopTracer{}
	}
	return m.tracer
}

// Metrics returns the configured metrics, or NoopMetrics if none is set.
func (m *JWTMiddleware) Metrics() Metrics {
	if m.metrics == nil {
		return &NoopMetrics{}
	}
	return m.metrics
}

// GetClaimsWithKey retrieves validated claims from context using a custom key.
func GetClaimsWithKey(ctx context.Context, key string) (*validator.ValidatedClaims, error) {
	if key == "" {
		key = DefaultClaimsKey.Name
	}
	claims := ctx.Value(ContextKey{Name: key})
	if claims == nil {
		return nil, ErrMissingClaims
	}
	validatedClaims, ok := claims.(*validator.ValidatedClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}
	return validatedClaims, nil
}

// GetClaims retrieves validated claims from context using the default key.
func GetClaims(ctx context.Context) (*validator.ValidatedClaims, error) {
	return GetClaimsWithKey(ctx, DefaultClaimsKey.Name)
}
