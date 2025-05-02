package jwtgin

import (
	"errors"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gin-gonic/gin"
)

// GinMiddlewareConfig holds configuration for the Gin adapter.
type GinMiddlewareConfig struct {
	errorHandler func(*gin.Context, error)
}

// New creates a Gin middleware for JWT authentication.
//
//   - validateToken: your jwtmiddleware.ValidateToken implementation (e.g. validator.ValidateToken).
//   - coreOpts: core jwtmiddleware options (can be nil or empty, e.g. WithContextKey).
//   - ginOpts: Gin-specific options (e.g. WithErrorHandler).
//
// Claims are always stored in Go context using the core context key (struct with Name field).
// Use jwtgin.GetClaims(c) or jwtgin.GetClaimsWithKey(c, key) to retrieve claims in handlers.
func New(
	validateToken jwtmiddleware.ValidateToken,
	coreOpts []jwtmiddleware.Option, // core options
	ginOpts ...Option, // Gin-specific options
) gin.HandlerFunc {
	config := &GinMiddlewareConfig{
		errorHandler: defaultGinErrorHandler,
	}

	// Apply Gin-specific options
	for _, opt := range ginOpts {
		opt(config)
	}

	// Always add Gin error handler bridge first
	middlewareOpts := []jwtmiddleware.Option{
		jwtmiddleware.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			c, exists := r.Context().Value(gin.ContextKey).(*gin.Context)
			if !exists || c == nil {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			config.errorHandler(c, err)
		}),
	}

	middlewareOpts = append(middlewareOpts, coreOpts...)

	coreMiddleware := jwtmiddleware.New(validateToken, middlewareOpts...)
	tracer := coreMiddleware.Tracer()
	metrics := coreMiddleware.Metrics()
	logger := coreMiddleware.Logger()

	return func(c *gin.Context) {
		span := tracer.StartSpan("gin.middleware", c.Request.Method, c.Request.URL.Path)
		defer span.Finish()
		metrics.IncCounter("gin.requests", map[string]string{"path": c.Request.URL.Path, "method": c.Request.Method})
		if logger != nil && coreMiddleware.LogLevel() >= jwtmiddleware.LogLevelDebug {
			logger.Debugf("Gin: Entering JWT middleware for %s %s", c.Request.Method, c.Request.URL.Path)
		}
		encounteredError := true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			c.Request = r

			// No longer set claims in Gin context; only Go context is used
			c.Next()
		}

		coreMiddleware.CheckJWT(handler).ServeHTTP(c.Writer, c.Request)

		if encounteredError {
			span.SetTag("jwt_validation_failed", true)
			metrics.IncCounter("gin.jwt_validation_failed", map[string]string{"path": c.Request.URL.Path, "method": c.Request.Method})
			if logger != nil && coreMiddleware.LogLevel() >= jwtmiddleware.LogLevelWarn {
				logger.Warnf("Gin: JWT validation failed for %s %s", c.Request.Method, c.Request.URL.Path)
			}
			c.Abort()
		} else {
			span.SetTag("jwt_validated", true)
			metrics.IncCounter("gin.jwt_validated", map[string]string{"path": c.Request.URL.Path, "method": c.Request.Method})
		}
	}
}

// GetClaims returns validated claims from the Gin context using the same context key
// that was configured in the core middleware.
//
// Example usage:
//
//	func MyHandler(c *gin.Context) {
//		claims, err := jwtgin.GetClaims(c)
//		if err != nil {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
//			return
//		}
//		// Use claims.CustomClaims and claims.RegisteredClaims
//		c.JSON(http.StatusOK, gin.H{"subject": claims.RegisteredClaims.Subject})
//	}
func GetClaims(c *gin.Context) (*validator.ValidatedClaims, error) {
	return jwtmiddleware.GetClaimsWithKey(c.Request.Context(), jwtmiddleware.DefaultClaimsKey.Name)
}

// GetClaimsWithKey returns validated claims from the Gin context using a custom key.
// Use this when you've configured the core middleware with jwtmiddleware.WithContextKey.
//
// Example usage:
//
//	// When setting up middleware:
//	coreOpts := []jwtmiddleware.Option{
//	    jwtmiddleware.WithContextKey("my-custom-key"),
//	}
//	middleware := jwtgin.New(validateToken, coreOpts)
//
//	// In your handler:
//	func MyHandler(c *gin.Context) {
//		claims, err := jwtgin.GetClaimsWithKey(c, "my-custom-key")
//		if err != nil {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
//			return
//		}
//		// Use the claims...
//	}
func GetClaimsWithKey(c *gin.Context, key string) (*validator.ValidatedClaims, error) {
	return jwtmiddleware.GetClaimsWithKey(c.Request.Context(), key)
}

// MustGetClaims returns validated claims from the Gin context or aborts the request with 401 if not present.
// This is a convenience function for handlers that require valid claims.
//
// Example usage:
//
//	func ProtectedHandler(c *gin.Context) {
//		claims := jwtgin.MustGetClaims(c)
//		if claims == nil {
//			return // request has been aborted, no need to continue
//		}
//		// Use the claims...
//		c.JSON(http.StatusOK, gin.H{"message": "Protected data for " + claims.RegisteredClaims.Subject})
//	}
func MustGetClaims(c *gin.Context) *validator.ValidatedClaims {
	claims, err := GetClaims(c)
	if err != nil || claims == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Failed to get validated JWT claims."})
		c.Abort()
		return nil
	}
	return claims
}

// defaultGinErrorHandler is the default error handler for Gin.
// It follows the same error format as the core middleware.
func defaultGinErrorHandler(c *gin.Context, err error) {
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

	c.AbortWithStatusJSON(statusCode, result)
}
