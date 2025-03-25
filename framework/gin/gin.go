package jwtginhandler

import (
	"errors"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gin-gonic/gin"
)

const DefaultClaimsKey = "jwt"

var (
	ErrMissingClaims = errors.New("no JWT claims found in context")
	ErrInvalidClaims = errors.New("invalid JWT claims type")
)

type GinMiddlewareConfig struct {
	errorHandler   func(*gin.Context, error)
	contextKey     string
	tokenExtractor jwtmiddleware.TokenExtractor
}

// NewGinMiddleware creates a Gin middleware for JWT authentication.
// The validateToken should be an implementation of jwtmiddleware.ValidateToken,
// typically a validator.Validator instance. Ensure that the validateToken
// implementation is thread-safe and does not have mutable state that could be
// altered concurrently.
func NewGinMiddleware(validateToken jwtmiddleware.ValidateToken, opts ...Option) gin.HandlerFunc {
	config := &GinMiddlewareConfig{
		errorHandler: defaultGinErrorHandler,
		contextKey:   DefaultClaimsKey,
	}

	for _, opt := range opts {
		opt(config)
	}

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

	if config.tokenExtractor != nil {
		middlewareOpts = append(middlewareOpts, jwtmiddleware.WithTokenExtractor(config.tokenExtractor))
	}

	middleware := jwtmiddleware.New(validateToken, middlewareOpts...)

	return func(c *gin.Context) {
		encounteredError := true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			c.Request = r

			if claims, ok := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims); ok {
				c.Set(config.contextKey, claims)
			}

			c.Next()
		}

		middleware.CheckJWT(handler).ServeHTTP(c.Writer, c.Request)

		if encounteredError {
			c.Abort()
		}
	}
}

func defaultGinErrorHandler(c *gin.Context, err error) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error": err.Error(),
	})
}

func GetClaims(c *gin.Context, contextKey string) (*validator.ValidatedClaims, error) {
	if contextKey == "" {
		contextKey = DefaultClaimsKey
	}
	claims, exists := c.Get(contextKey)
	if !exists {
		return nil, ErrMissingClaims
	}

	validatedClaims, ok := claims.(*validator.ValidatedClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	return validatedClaims, nil
}
