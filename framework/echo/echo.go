package jwtecho

import (
	"errors"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/labstack/echo/v4"
)

// echoMiddlewareConfig holds configuration for the Echo adapter.
type echoMiddlewareConfig struct {
	errorHandler func(echo.Context, error)
}

// New creates an Echo middleware for JWT authentication.
//
//   - validateToken: your jwtmiddleware.ValidateToken implementation (e.g. validator.ValidateToken).
//   - coreOpts: core jwtmiddleware options (can be nil or empty, e.g. WithContextKey).
//   - echoOpts: Echo-specific options (e.g. WithErrorHandler).
//
// Claims are always stored in Go context using the core context key (struct with Name field).
// Use jwtecho.GetClaims(c) or jwtecho.GetClaimsWithKey(c, key) to retrieve claims in handlers.
func New(
	validateToken jwtmiddleware.ValidateToken,
	coreOpts []jwtmiddleware.Option, // core options
	echoOpts ...Option, // Echo-specific options
) echo.MiddlewareFunc {
	config := &echoMiddlewareConfig{
		errorHandler: defaultEchoErrorHandler,
	}

	// Apply Echo-specific options
	for _, opt := range echoOpts {
		opt(config)
	}

	// Always add Echo error handler bridge first
	middlewareOpts := []jwtmiddleware.Option{
		jwtmiddleware.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			e := echo.New()
			c := e.NewContext(r, w)
			config.errorHandler(c, err)
		}),
	}

	middlewareOpts = append(middlewareOpts, coreOpts...)

	coreMiddleware := jwtmiddleware.New(validateToken, middlewareOpts...)
	tracer := coreMiddleware.Tracer()
	metrics := coreMiddleware.Metrics()
	logger := coreMiddleware.Logger()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			span := tracer.StartSpan("echo.middleware", c.Request().Method, c.Request().URL.Path)
			defer span.Finish()
			metrics.IncCounter("echo.requests", map[string]string{"path": c.Request().URL.Path, "method": c.Request().Method})
			if logger != nil && coreMiddleware.LogLevel() >= jwtmiddleware.LogLevelDebug {
				logger.Debugf("Echo: Entering JWT middleware for %s %s", c.Request().Method, c.Request().URL.Path)
			}
			encounteredError := true
			var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
				encounteredError = false
				c.SetRequest(r)
				err := next(c)
				if err != nil {
					return
				}
			}
			coreMiddleware.CheckJWT(handler).ServeHTTP(c.Response(), c.Request())
			if encounteredError {
				span.SetTag("jwt_validation_failed", true)
				metrics.IncCounter("echo.jwt_validation_failed", map[string]string{"path": c.Request().URL.Path, "method": c.Request().Method})
				if logger != nil && coreMiddleware.LogLevel() >= jwtmiddleware.LogLevelWarn {
					logger.Warnf("Echo: JWT validation failed for %s %s", c.Request().Method, c.Request().URL.Path)
				}
				return nil // Prevent further handlers from being called
			}
			span.SetTag("jwt_validated", true)
			metrics.IncCounter("echo.jwt_validated", map[string]string{"path": c.Request().URL.Path, "method": c.Request().Method})
			return nil
		}
	}
}

// GetClaims returns validated claims from the Echo context using the same context key
// that was configured in the core middleware.
//
// Example usage:
//
//	func myHandler(c echo.Context) error {
//		claims, err := jwtecho.GetClaims(c)
//		if err != nil {
//			return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
//		}
//		// Use claims.CustomClaims and claims.RegisteredClaims
//		return c.JSON(http.StatusOK, map[string]string{"subject": claims.RegisteredClaims.Subject})
//	}
func GetClaims(c echo.Context) (*validator.ValidatedClaims, error) {
	return jwtmiddleware.GetClaimsWithKey(c.Request().Context(), jwtmiddleware.DefaultClaimsKey.Name)
}

// GetClaimsWithKey returns validated claims from the Echo context using a custom key.
// Use this when you've configured the core middleware with jwtmiddleware.WithContextKey.
//
// Example usage:
//
//	// When setting up middleware:
//	coreOpts := []jwtmiddleware.Option{
//	    jwtmiddleware.WithContextKey("my-custom-key"),
//	}
//	middleware := jwtecho.New(validateToken, coreOpts)
//
//	// In your handler:
//	func myHandler(c echo.Context) error {
//		claims, err := jwtecho.GetClaimsWithKey(c, "my-custom-key")
//		if err != nil {
//			return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
//		}
//		// Use the claims...
//		return c.JSON(http.StatusOK, map[string]interface{}{"userData": claims.CustomClaims})
//	}
func GetClaimsWithKey(c echo.Context, key string) (*validator.ValidatedClaims, error) {
	return jwtmiddleware.GetClaimsWithKey(c.Request().Context(), key)
}

// MustGetClaims returns validated claims from the Echo context or returns a 401 error if not present.
// This is a convenience function for handlers that require valid claims.
//
// Example usage:
//
//	func protectedHandler(c echo.Context) error {
//		claims, err := jwtecho.MustGetClaims(c)
//		if err != nil {
//			return err // Error response already sent
//		}
//		// Use the claims...
//		return c.JSON(http.StatusOK, map[string]string{
//			"message": "Protected data for " + claims.RegisteredClaims.Subject,
//		})
//	}
func MustGetClaims(c echo.Context) (*validator.ValidatedClaims, error) {
	claims, err := GetClaims(c)
	if err != nil || claims == nil {
		errorResponse := map[string]string{"message": "Failed to get validated JWT claims."}
		errResp := c.JSON(http.StatusUnauthorized, errorResponse)
		return nil, errResp
	}
	return claims, nil
}

// defaultEchoErrorHandler is the default error handler for Echo.
// It follows the same error format as the core middleware.
func defaultEchoErrorHandler(c echo.Context, err error) {
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

	// Create the response object
	response := make(map[string]string)
	for k, v := range result {
		response[k] = v
	}

	err = c.JSON(statusCode, response)
	if err != nil {
		return
	}
}
