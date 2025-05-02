package jwtgin

import (
	"github.com/gin-gonic/gin"
)

// Option defines a functional option for configuring the middleware
type Option func(*GinMiddlewareConfig)

// WithErrorHandler sets a custom error handler for the middleware
func WithErrorHandler(handler func(*gin.Context, error)) Option {
	return func(config *GinMiddlewareConfig) {
		config.errorHandler = handler
	}
}
