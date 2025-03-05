package jwtginhandler

import (
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gin-gonic/gin"
)

// ginMiddlewareConfig holds all configuration for the middleware
type ginMiddlewareConfig struct {
	errorHandler   func(*gin.Context, error)
	contextKey     string
	tokenExtractor jwtmiddleware.TokenExtractor
}

// GinMiddleware is a constructor for the Gin middleware with improved DX
func GinMiddleware(validateToken jwtmiddleware.ValidateToken, opts ...Option) gin.HandlerFunc {
	// Set default config
	config := &ginMiddlewareConfig{
		errorHandler: defaultGinErrorHandler,
		contextKey:   "jwt", // Default context key for claims
	}

	// Apply all options
	for _, opt := range opts {
		opt(config)
	}

	// Create middleware with configured options
	middlewareOpts := []jwtmiddleware.Option{
		jwtmiddleware.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			// Retrieve the Gin context from the request
			c, _ := r.Context().Value(gin.ContextKey).(*gin.Context)
			if c == nil {
				// Fallback if context is not available
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(err.Error()))
				return
			}
			config.errorHandler(c, err)
		}),
	}

	if config.tokenExtractor != nil {
		middlewareOpts = append(middlewareOpts, jwtmiddleware.WithTokenExtractor(config.tokenExtractor))
	}

	middleware := jwtmiddleware.New(validateToken, middlewareOpts...)

	return func(c *gin.Context) {
		encounteredError := true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			c.Request = r

			// Store the claims in context if validation succeeded
			if claims, ok := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims); ok {
				c.Set(config.contextKey, claims)
			}

			c.Next()
		}

		middleware.CheckJWT(handler).ServeHTTP(c.Writer, c.Request)

		if encounteredError {
			c.Abort() // Prevent further handlers from being called.
		}
	}
}

func defaultGinErrorHandler(c *gin.Context, err error) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"message": err.Error(),
	})
}

// NewGinMiddleware is a constructor for the Gin middleware.
// Deprecated: Use GinMiddleware instead.
func NewGinMiddleware(jwtValidator *validator.Validator, options ...Option) gin.HandlerFunc {
	return GinMiddleware(jwtValidator.ValidateToken, options...)
}
