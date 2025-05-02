package jwtgrpc

import (
	"context"
)

// Option defines a functional option for configuring the gRPC adapter.
type Option func(*grpcMiddlewareConfig)

// WithErrorHandler sets a custom gRPC error handler.
func WithErrorHandler(handler func(ctx context.Context, err error) error) Option {
	return func(config *grpcMiddlewareConfig) {
		config.errorHandler = handler
	}
}

// WithExcludedMethods allows configuring a list of gRPC methods to exclude from JWT validation.
func WithExcludedMethods(methods []string) Option {
	methodSet := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		methodSet[m] = struct{}{}
	}
	return func(cfg *grpcMiddlewareConfig) {
		cfg.exclusionChecker = func(method string) bool {
			_, ok := methodSet[method]
			return ok
		}
	}
}

// WithExclusionChecker allows configuring a custom exclusion checker for gRPC methods.
func WithExclusionChecker(checker func(string) bool) Option {
	return func(cfg *grpcMiddlewareConfig) {
		cfg.exclusionChecker = checker
	}
}
