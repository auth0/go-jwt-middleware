package jwtginhandler

import (
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/gin-gonic/gin"
)

// Option defines a functional option for configuring the middleware
type Option func(*ginMiddlewareConfig)

// WithErrorHandler sets a custom error handler
// WithErrorHandler sets a custom error handler for the middleware
func WithErrorHandler(handler func(*gin.Context, error)) Option {
	return func(config *ginMiddlewareConfig) {
		config.errorHandler = handler
	}
}

// WithContextKey sets a custom context key for storing the JWT claims
func WithContextKey(key string) Option {
	return func(config *ginMiddlewareConfig) {
		config.contextKey = key
	}
}

// WithTokenExtractor sets a custom token extractor
func WithTokenExtractor(extractor jwtmiddleware.TokenExtractor) Option {
	return func(config *ginMiddlewareConfig) {
		config.tokenExtractor = extractor
	}
}
