package jwtecho

import (
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
