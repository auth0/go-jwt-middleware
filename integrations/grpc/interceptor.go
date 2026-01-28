package grpc

import (
	"context"
	"errors"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"google.golang.org/grpc"
)

// JWTInterceptor provides JWT validation for gRPC servers.
type JWTInterceptor struct {
	core            *core.Core
	tokenExtractor  TokenExtractor
	errorHandler    ErrorHandler
	excludedMethods map[string]bool
	logger          Logger

	// Internal builder for accumulating core options
	coreBuilder *coreBuilder
}

// New creates a new gRPC JWT interceptor with the provided options.
// WithValidator option is required.
func New(opts ...Option) (*JWTInterceptor, error) {
	interceptor := &JWTInterceptor{
		tokenExtractor:  MetadataTokenExtractor,
		errorHandler:    DefaultErrorHandler,
		excludedMethods: make(map[string]bool),
	}

	for _, opt := range opts {
		if err := opt(interceptor); err != nil {
			return nil, err
		}
	}

	// Build core from accumulated options if builder was used
	if interceptor.core == nil && interceptor.coreBuilder != nil {
		c, err := interceptor.coreBuilder.build()
		if err != nil {
			return nil, err
		}
		interceptor.core = c
	}

	if interceptor.core == nil {
		return nil, errors.New("validator is required, use WithValidator option")
	}

	return interceptor, nil
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
