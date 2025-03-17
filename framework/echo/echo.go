package jwtechohandler

import (
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/labstack/echo/v4"
)

var DefaultClaimsKey = "jwt"

// echoMiddlewareConfig holds all configuration for the middleware
type echoMiddlewareConfig struct {
	errorHandler   func(echo.Context, error)
	contextKey     string
	tokenExtractor jwtmiddleware.TokenExtractor
}

// NewEchoMiddleware is a constructor for the Echo middleware with improved DX
func NewEchoMiddleware(validateToken jwtmiddleware.ValidateToken, opts ...Option) echo.MiddlewareFunc {
	// Set default config
	config := &echoMiddlewareConfig{
		errorHandler: defaultEchoErrorHandler,
		contextKey:   DefaultClaimsKey, // Default context key for claims
	}

	// Apply all options
	for _, opt := range opts {
		opt(config)
	}

	// Create middleware with configured options
	middlewareOpts := []jwtmiddleware.Option{
		jwtmiddleware.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			// Adapt the standard error handler to the Echo context
			e := echo.New()
			c := e.NewContext(r, w)
			config.errorHandler(c, err)
		}),
	}

	if config.tokenExtractor != nil {
		middlewareOpts = append(middlewareOpts, jwtmiddleware.WithTokenExtractor(config.tokenExtractor))
	}

	middleware := jwtmiddleware.New(validateToken, middlewareOpts...)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			encounteredError := true
			var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
				encounteredError = false
				c.SetRequest(r)

				// Store the claims in context if validation succeeded
				if claims, ok := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims); ok {
					c.Set(config.contextKey, claims)
				}

				err := next(c)
				if err != nil {
					return
				}
			}

			middleware.CheckJWT(handler).ServeHTTP(c.Response(), c.Request())

			if encounteredError {
				return nil // Prevent further handlers from being called
			}
			return nil
		}
	}
}

func defaultEchoErrorHandler(c echo.Context, err error) {
	err = c.JSON(http.StatusUnauthorized, map[string]string{
		"message": err.Error(),
	})
	if err != nil {
		return
	}
}

// GetClaims extracts the JWT claims from the Echo context
func GetClaims(c echo.Context, contextKey string) (*validator.ValidatedClaims, bool) {
	claims := c.Get(contextKey)
	if claims == nil {
		return nil, false
	}

	validatedClaims, ok := claims.(*validator.ValidatedClaims)
	return validatedClaims, ok
}
