package grpc

import (
	"context"
	"fmt"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"google.golang.org/grpc"
)

// JWTInterceptor provides JWT validation for gRPC servers.
type JWTInterceptor struct {
	core            *core.Core
	tokenExtractor  TokenExtractor
	errorHandler    ErrorHandler
	excludedMethods map[string]bool
	logger          Logger

	// Temporary fields used during construction
	validator           *validator.Validator
	credentialsOptional bool
}

// New creates a new gRPC JWT interceptor with the provided options.
// WithValidator option is required.
//
// Example:
//
//	interceptor, err := grpc.New(
//	    grpc.WithValidator(validator),
//	    grpc.WithCredentialsOptional(false),
//	)
//	if err != nil {
//	    log.Fatalf("failed to create interceptor: %v", err)
//	}
func New(opts ...Option) (*JWTInterceptor, error) {
	interceptor := &JWTInterceptor{
		excludedMethods:     make(map[string]bool),
		credentialsOptional: false, // Credentials required by default
	}

	// Apply all options
	for _, opt := range opts {
		if err := opt(interceptor); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Validate required configuration
	if interceptor.validator == nil {
		return nil, ErrValidatorNil
	}

	// Apply defaults for optional fields not set by options
	interceptor.applyDefaults()

	// Create the core with the configured validator and options
	if err := interceptor.createCore(); err != nil {
		return nil, fmt.Errorf("failed to create core: %w", err)
	}

	return interceptor, nil
}

// applyDefaults sets secure default values for optional fields.
func (i *JWTInterceptor) applyDefaults() {
	if i.tokenExtractor == nil {
		i.tokenExtractor = MetadataTokenExtractor
	}
	if i.errorHandler == nil {
		i.errorHandler = DefaultErrorHandler
	}
}

// createCore creates the core.Core instance with the configured options.
func (i *JWTInterceptor) createCore() error {
	// Wrap validator in adapter that implements core.Validator interface
	adapter := &validatorAdapter{validator: i.validator}

	// Build core options
	coreOpts := []core.Option{
		core.WithValidator(adapter),
		core.WithCredentialsOptional(i.credentialsOptional),
	}

	// Add logger if configured
	if i.logger != nil {
		coreOpts = append(coreOpts, core.WithLogger(i.logger))
	}

	coreInstance, err := core.New(coreOpts...)
	if err != nil {
		return err
	}
	i.core = coreInstance
	return nil
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that validates JWTs.
// It extracts the JWT from gRPC metadata, validates it, and makes the claims
// available in the request context.
func (i *JWTInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if method is excluded
		if i.excludedMethods[info.FullMethod] {
			if i.logger != nil {
				i.logger.Debug("skipping JWT validation for excluded method",
					"method", info.FullMethod)
			}
			return handler(ctx, req)
		}

		// Validate and enrich context
		validatedCtx, err := i.validateRequest(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		// Call handler with validated context
		return handler(validatedCtx, req)
	}
}

// StreamServerInterceptor returns a grpc.StreamServerInterceptor that validates JWTs.
// It extracts the JWT from gRPC metadata, validates it, and makes the claims
// available in the stream context.
func (i *JWTInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Check if method is excluded
		if i.excludedMethods[info.FullMethod] {
			if i.logger != nil {
				i.logger.Debug("skipping JWT validation for excluded method",
					"method", info.FullMethod)
			}
			return handler(srv, ss)
		}

		// Validate and enrich context
		validatedCtx, err := i.validateRequest(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		// Wrap stream with validated context
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          validatedCtx,
		}

		return handler(srv, wrappedStream)
	}
}

// validateRequest extracts and validates the JWT from the context.
func (i *JWTInterceptor) validateRequest(ctx context.Context, method string) (context.Context, error) {
	if i.logger != nil {
		i.logger.Debug("extracting JWT from gRPC metadata",
			"method", method)
	}

	// Extract token
	token, err := i.tokenExtractor(ctx)
	if err != nil {
		if i.logger != nil {
			i.logger.Error("failed to extract token from gRPC metadata",
				"error", err,
				"method", method)
		}
		return ctx, i.errorHandler(err)
	}

	if i.logger != nil {
		i.logger.Debug("validating JWT",
			"method", method)
	}

	// Validate token
	claims, err := i.core.CheckToken(ctx, token)
	if err != nil {
		if i.logger != nil {
			i.logger.Warn("JWT validation failed",
				"error", err,
				"method", method)
		}
		return ctx, i.errorHandler(err)
	}

	// Set claims in context (if any)
	if claims != nil {
		if i.logger != nil {
			i.logger.Debug("JWT validation successful, setting claims in context",
				"method", method)
		}
		ctx = core.SetClaims(ctx, claims)
	} else if i.logger != nil {
		i.logger.Debug("no credentials provided, continuing without claims (credentials optional)",
			"method", method)
	}

	return ctx, nil
}

// wrappedServerStream wraps grpc.ServerStream with a custom context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context with JWT claims.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
