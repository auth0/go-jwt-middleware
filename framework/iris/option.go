package jwtiris

import (
	"github.com/kataras/iris/v12"
)

// Option is a function that configures the middleware
type Option func(*IrisMiddlewareConfig)

// WithErrorHandler sets a custom error handler
func WithErrorHandler(handler func(iris.Context, error)) Option {
	return func(config *IrisMiddlewareConfig) {
		config.errorHandler = handler
	}
}
