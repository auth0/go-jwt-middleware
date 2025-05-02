package jwtiris

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/kataras/iris/v12"
)

// ContextKey is used to store the Iris context in the request context
type contextKey struct{}

// IrisContextKey is the key used to store the Iris context in the request context
var IrisContextKey = contextKey{}

// IrisMiddlewareConfig holds configuration for the Iris adapter.
type IrisMiddlewareConfig struct {
	errorHandler func(iris.Context, error)
}

// New creates an Iris middleware for JWT authentication.
//
//   - validateToken: your jwtmiddleware.ValidateToken implementation (e.g. validator.ValidateToken).
//   - coreOpts: core jwtmiddleware options (can be nil or empty, e.g. WithContextKey).
//   - irisOpts: Iris-specific options (e.g. WithErrorHandler).
//
// Claims are always stored in Go context using the core context key (struct with Name field).
// Use jwtiris.GetClaims(c) or jwtiris.GetClaimsWithKey(c, key) to retrieve claims in handlers.
func New(
	validateToken jwtmiddleware.ValidateToken,
	coreOpts []jwtmiddleware.Option, // core options
	irisOpts ...Option, // Iris-specific options
) iris.Handler {
	config := &IrisMiddlewareConfig{
		errorHandler: defaultIrisErrorHandler,
	}

	// Apply Iris-specific options
	for _, opt := range irisOpts {
		opt(config)
	}

	// Always add Iris error handler bridge first
	middlewareOpts := []jwtmiddleware.Option{
		jwtmiddleware.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			// Try to get Iris context from request context
			c, ok := r.Context().Value(IrisContextKey).(iris.Context)
			if !ok || c == nil {
				// Fall back to direct response if no Iris context is available
				w.Header().Set("Content-Type", "application/json")

				// Use the same error handling logic as the core middleware
				result := jwtmiddleware.ErrorToJSON(err)

				// Determine the status code
				statusCode := http.StatusUnauthorized
				var jwtErr *jwtmiddleware.JWTError
				if errors.As(err, &jwtErr) {
					statusCode = jwtErr.StatusCode
				} else if errors.Is(err, jwtmiddleware.ErrJWTMissing) {
					statusCode = http.StatusBadRequest
				}

				w.WriteHeader(statusCode)

				// Convert map to JSON bytes
				jsonBytes, _ := json.Marshal(result)
				_, _ = w.Write(jsonBytes)
				return
			}

			// Use the custom error handler with the Iris context
			config.errorHandler(c, err)
		}),
	}

	middlewareOpts = append(middlewareOpts, coreOpts...)

	coreMiddleware := jwtmiddleware.New(validateToken, middlewareOpts...)
	tracer := coreMiddleware.Tracer()
	metrics := coreMiddleware.Metrics()
	logger := coreMiddleware.Logger()

	return func(c iris.Context) {
		span := tracer.StartSpan("iris.middleware", c.Method(), c.Path())
		defer span.Finish()
		metrics.IncCounter("iris.requests", map[string]string{"path": c.Path(), "method": c.Method()})
		if logger != nil && coreMiddleware.LogLevel() >= jwtmiddleware.LogLevelDebug {
			logger.Debugf("Iris: Entering JWT middleware for %s %s", c.Method(), c.Path())
		}

		// Store Iris context in request context
		req := c.Request().WithContext(context.WithValue(c.Request().Context(), IrisContextKey, c))
		c.ResetRequest(req)

		encounteredError := true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			c.ResetRequest(r)
			c.Next()
		}

		coreMiddleware.CheckJWT(handler).ServeHTTP(c.ResponseWriter(), c.Request())

		if encounteredError {
			span.SetTag("jwt_validation_failed", true)
			metrics.IncCounter("iris.jwt_validation_failed", map[string]string{"path": c.Path(), "method": c.Method()})
			if logger != nil && coreMiddleware.LogLevel() >= jwtmiddleware.LogLevelWarn {
				logger.Warnf("Iris: JWT validation failed for %s %s", c.Method(), c.Path())
			}
			c.StopExecution()
		} else {
			span.SetTag("jwt_validated", true)
			metrics.IncCounter("iris.jwt_validated", map[string]string{"path": c.Path(), "method": c.Method()})
		}
	}
}

// GetClaims returns validated claims from the Iris context using the same context key
// that was configured in the core middleware.
//
// Example usage:
//
//	func MyHandler(c iris.Context) {
//		claims, err := jwtiris.GetClaims(c)
//		if err != nil {
//			c.StopWithJSON(iris.StatusUnauthorized, map[string]string{"error": err.Error()})
//			return
//		}
//		// Use claims.CustomClaims and claims.RegisteredClaims
//		c.JSON(map[string]string{"subject": claims.RegisteredClaims.Subject})
//	}
func GetClaims(c iris.Context) (*validator.ValidatedClaims, error) {
	return jwtmiddleware.GetClaimsWithKey(c.Request().Context(), jwtmiddleware.DefaultClaimsKey.Name)
}

// GetClaimsWithKey returns validated claims from the Iris context using a custom key.
// Use this when you've configured the core middleware with jwtmiddleware.WithContextKey.
//
// Example usage:
//
//	// When setting up middleware:
//	coreOpts := []jwtmiddleware.Option{
//	    jwtmiddleware.WithContextKey("my-custom-key"),
//	}
//	middleware := jwtiris.New(validateToken, coreOpts)
//
//	// In your handler:
//	func MyHandler(c iris.Context) {
//		claims, err := jwtiris.GetClaimsWithKey(c, "my-custom-key")
//		if err != nil {
//			c.StopWithJSON(iris.StatusUnauthorized, map[string]string{"error": err.Error()})
//			return
//		}
//		// Use the claims...
//	}
func GetClaimsWithKey(c iris.Context, key string) (*validator.ValidatedClaims, error) {
	return jwtmiddleware.GetClaimsWithKey(c.Request().Context(), key)
}

// MustGetClaims returns validated claims from the Iris context or stops execution
// with a 401 error if not present. This is a convenience function for handlers
// that require valid claims.
//
// Example usage:
//
//	func ProtectedHandler(c iris.Context) {
//			claims := jwtiris.MustGetClaims(c)
//			if claims == nil {
//				return // Error response already sent, no need to continue
//			}
//			// Use the claims...
//			c.JSON(map[string]string{"message": "Protected data for " + claims.RegisteredClaims.Subject})
//	}
func MustGetClaims(c iris.Context) *validator.ValidatedClaims {
	claims, err := GetClaims(c)
	if err != nil || claims == nil {
		c.StopWithJSON(iris.StatusUnauthorized, map[string]string{"message": "Failed to get validated JWT claims."})
		c.StopExecution()
		return nil
	}
	return claims
}

// defaultIrisErrorHandler is the default error handler for Iris.
// It follows the same error format as the core middleware.
func defaultIrisErrorHandler(c iris.Context, err error) {
	// Use the same error handling logic as the core middleware
	result := jwtmiddleware.ErrorToJSON(err)

	// Determine the status code
	statusCode := http.StatusUnauthorized
	var jwtErr *jwtmiddleware.JWTError
	if errors.As(err, &jwtErr) {
		statusCode = jwtErr.StatusCode
	} else if errors.Is(err, jwtmiddleware.ErrJWTMissing) {
		statusCode = http.StatusBadRequest
	}

	c.StopWithJSON(statusCode, result)
}
