package jwtechohandler

import (
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/labstack/echo/v4"
)

// Option is a function that configures the middleware
type Option func(*echoMiddlewareConfig)

// WithErrorHandler sets a custom error handler
func WithErrorHandler(handler func(echo.Context, error)) Option {
	return func(config *echoMiddlewareConfig) {
		config.errorHandler = handler
	}
}

// WithContextKey sets a custom context key to store claims
func WithContextKey(key string) Option {
	return func(config *echoMiddlewareConfig) {
		config.contextKey = key
	}
}

// WithTokenExtractor sets a custom token extractor
func WithTokenExtractor(extractor jwtmiddleware.TokenExtractor) Option {
	return func(config *echoMiddlewareConfig) {
		config.tokenExtractor = extractor
	}
}
