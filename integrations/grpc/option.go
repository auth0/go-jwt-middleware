package grpc

import (
	"context"
	"errors"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

// Option configures the JWT interceptor.
type Option func(*JWTInterceptor) error

// Logger defines an optional logging interface compatible with log/slog.
// This is the same interface used by core for consistent logging across the stack.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// validatorAdapter adapts validator.Validator to core.Validator interface.
type validatorAdapter struct {
	validator *validator.Validator
}

func (v *validatorAdapter) ValidateToken(ctx context.Context, token string) (any, error) {
	return v.validator.ValidateToken(ctx, token)
}

func (v *validatorAdapter) ValidateDPoPProof(ctx context.Context, proofString string) (core.DPoPProofClaims, error) {
	return v.validator.ValidateDPoPProof(ctx, proofString)
}

// coreBuilder helps build a core.Core with accumulated options.
type coreBuilder struct {
	validator           *validator.Validator
	credentialsOptional *bool
	logger              Logger
}

func (b *coreBuilder) build() (*core.Core, error) {
	if b.validator == nil {
		return nil, errors.New("validator is required")
	}

	adapter := &validatorAdapter{validator: b.validator}
	opts := []core.Option{
		core.WithValidator(adapter),
	}

	if b.credentialsOptional != nil {
		opts = append(opts, core.WithCredentialsOptional(*b.credentialsOptional))
	}
	if b.logger != nil {
		opts = append(opts, core.WithLogger(b.logger))
	}

	return core.New(opts...)
}

// WithValidator sets the JWT validator (REQUIRED).
// This is the primary way to configure the interceptor.
//
// For advanced configuration (logging, error handling, etc.), combine with other With* options.
//
// Example:
//
//	interceptor, _ := grpc.New(
//	    grpc.WithValidator(validator),
//	    grpc.WithLogger(logger),
//	    grpc.WithCredentialsOptional(true),
//	)
func WithValidator(v *validator.Validator) Option {
	return func(i *JWTInterceptor) error {
		if v == nil {
			return errors.New("validator cannot be nil")
		}
		if i.coreBuilder == nil {
			i.coreBuilder = &coreBuilder{}
		}
		i.coreBuilder.validator = v
		return nil
	}
}

// WithCredentialsOptional allows requests without JWT tokens to proceed.
// When set to true, requests without tokens will not return an error,
// but the context will not contain any claims.
//
// Default: false (credentials required)
//
// Example:
//
//	interceptor, _ := grpc.New(
//	    grpc.WithValidator(validator),
//	    grpc.WithCredentialsOptional(true),
//	)
func WithCredentialsOptional(optional bool) Option {
	return func(i *JWTInterceptor) error {
		if i.coreBuilder == nil {
			i.coreBuilder = &coreBuilder{}
		}
		i.coreBuilder.credentialsOptional = &optional
		return nil
	}
}

// WithLogger sets an optional logger for the interceptor.
// The logger will be used throughout the validation flow in both interceptor and core.
//
// The logger interface is compatible with log/slog.Logger and similar loggers.
//
// Example:
//
//	interceptor, _ := grpc.New(
//	    grpc.WithValidator(validator),
//	    grpc.WithLogger(slog.Default()),
//	)
func WithLogger(logger Logger) Option {
	return func(i *JWTInterceptor) error {
		if logger == nil {
			return errors.New("logger cannot be nil")
		}
		if i.coreBuilder == nil {
			i.coreBuilder = &coreBuilder{}
		}
		i.coreBuilder.logger = logger
		i.logger = logger // Set on interceptor for its own logging
		return nil
	}
}

// WithTokenExtractor sets a custom token extractor function.
// Default is MetadataTokenExtractor which extracts from "authorization" metadata.
func WithTokenExtractor(extractor TokenExtractor) Option {
	return func(i *JWTInterceptor) error {
		if extractor == nil {
			return errors.New("token extractor cannot be nil")
		}
		i.tokenExtractor = extractor
		return nil
	}
}

// WithErrorHandler sets a custom error handler function.
// Default is DefaultErrorHandler which maps errors to gRPC status codes.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(i *JWTInterceptor) error {
		if handler == nil {
			return errors.New("error handler cannot be nil")
		}
		i.errorHandler = handler
		return nil
	}
}

// WithExcludedMethods excludes specific gRPC methods from JWT validation.
// Methods should be provided in the format: "/package.Service/Method"
// Example: "/myapp.MyService/PublicMethod", "/grpc.health.v1.Health/Check"
func WithExcludedMethods(methods ...string) Option {
	return func(i *JWTInterceptor) error {
		if i.excludedMethods == nil {
			i.excludedMethods = make(map[string]bool)
		}
		for _, method := range methods {
			i.excludedMethods[method] = true
		}
		return nil
	}
}
