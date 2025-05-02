package jwtgrpc

import (
	"context"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// Constants for context keys and metric names to avoid string literals
const (
	// Context key for JWT errors
	jwtErrorKey contextKey = "jwt_error"

	// Metric names
	metricUnaryRequests           = "grpc.unary_requests"
	metricUnaryExcluded           = "grpc.unary_excluded"
	metricUnaryJWTValidated       = "grpc.unary_jwt_validated"
	metricUnaryJWTValidationFail  = "grpc.unary_jwt_validation_failed"
	metricStreamRequests          = "grpc.stream_requests"
	metricStreamExcluded          = "grpc.stream_excluded"
	metricStreamJWTValidated      = "grpc.stream_jwt_validated"
	metricStreamJWTValidationFail = "grpc.stream_jwt_validation_failed"

	// Span names
	spanUnaryMiddleware  = "grpc.unary_middleware"
	spanStreamMiddleware = "grpc.stream_middleware"
)

// grpcMiddlewareConfig holds configuration for the gRPC adapter.
type grpcMiddlewareConfig struct {
	errorHandler     func(ctx context.Context, err error) error
	exclusionChecker func(method string) bool
}

// Middleware provides a unified gRPC JWT middleware with both unary and stream interceptors.
type Middleware struct {
	coreMiddleware *jwtmiddleware.JWTMiddleware
	config         *grpcMiddlewareConfig
}

// New creates a new gRPC JWT Middleware instance with both unary and stream interceptors.
func New(
	validateToken jwtmiddleware.ValidateToken,
	coreOpts []jwtmiddleware.Option,
	grpcOpts ...Option,
) *Middleware {
	config := &grpcMiddlewareConfig{
		errorHandler:     defaultGRPCErrorHandler,
		exclusionChecker: nil,
	}
	for _, opt := range grpcOpts {
		opt(config)
	}
	middlewareOpts := []jwtmiddleware.Option{
		jwtmiddleware.WithTokenExtractor(jwtmiddleware.GRPCMetadataTokenExtractor()),
		jwtmiddleware.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			ctx := context.WithValue(r.Context(), jwtErrorKey, err)
			*r = *r.WithContext(ctx)
		}),
	}
	middlewareOpts = append(middlewareOpts, coreOpts...)

	coreMiddleware := jwtmiddleware.New(validateToken, middlewareOpts...)
	return &Middleware{
		coreMiddleware: coreMiddleware,
		config:         config,
	}
}

// validateJWT is a helper function that handles the common JWT validation logic
// for both unary and stream interceptors.
func (m *Middleware) validateJWT(
	ctx context.Context,
	methodName string,
	logger jwtmiddleware.Logger,
	tracer jwtmiddleware.Tracer,
	metrics jwtmiddleware.Metrics,
	span jwtmiddleware.Span,
	isStream bool,
) (context.Context, error) {
	// Create a temporary HTTP request with the gRPC context
	r, _ := http.NewRequestWithContext(ctx, "POST", "/", nil)
	rr := &noopResponseWriter{}

	var jwtErr error
	m.coreMiddleware.CheckJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if logger != nil && m.coreMiddleware.LogLevel() >= jwtmiddleware.LogLevelDebug {
			logger.Debugf("gRPC: Entering JWT middleware for %s", methodName)
		}

		// Extract any error from the context
		jwtErr, _ = r.Context().Value(jwtErrorKey).(error)

		// If validation succeeded, copy claims to the gRPC context
		if jwtErr == nil {
			// Get the key from the core middleware
			key := m.coreMiddleware.GetContextKey()

			// Copy claims from the HTTP request context to the gRPC context
			if claims := r.Context().Value(key); claims != nil {
				ctx = context.WithValue(ctx, key, claims)
			}
		}
	})).ServeHTTP(rr, r)

	// Handle validation errors
	if jwtErr != nil {
		span.SetTag("jwt_validation_failed", true)

		metricName := metricUnaryJWTValidationFail
		if isStream {
			metricName = metricStreamJWTValidationFail
		}
		metrics.IncCounter(metricName, map[string]string{"method": methodName})

		if logger != nil && m.coreMiddleware.LogLevel() >= jwtmiddleware.LogLevelWarn {
			logger.Warnf("gRPC: JWT validation failed for %s: %v", methodName, jwtErr)
		}

		return ctx, jwtErr
	}

	// Validation succeeded
	span.SetTag("jwt_validated", true)

	metricName := metricUnaryJWTValidated
	if isStream {
		metricName = metricStreamJWTValidated
	}
	metrics.IncCounter(metricName, map[string]string{"method": methodName})

	return ctx, nil
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that validates JWT tokens
// before allowing access to unary gRPC methods.
func (m *Middleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	tracer := m.coreMiddleware.Tracer()
	metrics := m.coreMiddleware.Metrics()
	logger := m.coreMiddleware.Logger()
	config := m.config

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		span := tracer.StartSpan(spanUnaryMiddleware, info.FullMethod)
		defer span.Finish()
		metrics.IncCounter(metricUnaryRequests, map[string]string{"method": info.FullMethod})

		// Check if this method should be excluded from authentication
		if config.exclusionChecker != nil && config.exclusionChecker(info.FullMethod) {
			span.SetTag("excluded", true)
			metrics.IncCounter(metricUnaryExcluded, map[string]string{"method": info.FullMethod})
			return handler(ctx, req)
		}

		// Validate the JWT
		updatedCtx, jwtErr := m.validateJWT(ctx, info.FullMethod, logger, tracer, metrics, span, false)
		if jwtErr != nil {
			return nil, config.errorHandler(updatedCtx, jwtErr)
		}

		// Call the handler with the context containing the validated claims
		return handler(updatedCtx, req)
	}
}

// StreamServerInterceptor returns a grpc.StreamServerInterceptor that validates JWT tokens
// before allowing access to streaming gRPC methods.
func (m *Middleware) StreamServerInterceptor() grpc.StreamServerInterceptor {
	tracer := m.coreMiddleware.Tracer()
	metrics := m.coreMiddleware.Metrics()
	logger := m.coreMiddleware.Logger()
	config := m.config

	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		span := tracer.StartSpan(spanStreamMiddleware, info.FullMethod)
		defer span.Finish()
		metrics.IncCounter(metricStreamRequests, map[string]string{"method": info.FullMethod})

		// Check if this method should be excluded from authentication
		if config.exclusionChecker != nil && config.exclusionChecker(info.FullMethod) {
			span.SetTag("excluded", true)
			metrics.IncCounter(metricStreamExcluded, map[string]string{"method": info.FullMethod})
			return handler(srv, ss)
		}

		// Validate the JWT
		updatedCtx, jwtErr := m.validateJWT(ss.Context(), info.FullMethod, logger, tracer, metrics, span, true)
		if jwtErr != nil {
			return config.errorHandler(updatedCtx, jwtErr)
		}

		// Use the updated context with claims
		wrapped := &wrappedServerStream{ServerStream: ss, ctx: updatedCtx}
		return handler(srv, wrapped)
	}
}

// GetClaims returns validated claims from the gRPC context using the same context key
// that was configured in the core middleware.
//
// Example usage:
//
//	func (s *server) MyMethod(ctx context.Context, req *pb.Request) (*pb.Response, error) {
//		claims, err := jwtgrpc.GetClaims(ctx)
//		if err != nil {
//			return nil, status.Errorf(codes.Unauthenticated, "invalid auth: %v", err)
//		}
//		// Use claims.CustomClaims to access your custom claims
//		// Use claims.RegisteredClaims to access standard JWT claims like "sub", "exp", etc.
//		return &pb.Response{}, nil
//	}
func GetClaims(ctx context.Context) (*validator.ValidatedClaims, error) {
	return jwtmiddleware.GetClaimsWithKey(ctx, jwtmiddleware.DefaultClaimsKey.Name)
}

// GetClaimsWithKey returns validated claims from the gRPC context using a custom key.
// Use this when you've configured the core middleware with jwtmiddleware.WithContextKey.
//
// Example usage:
//
//	// When setting up middleware:
//	coreOpts := []jwtmiddleware.Option{
//	    jwtmiddleware.WithContextKey("my-custom-key"),
//	}
//	middleware := jwtgrpc.New(validateToken, coreOpts)
//
//	// In your handler:
//	func (s *server) MyMethod(ctx context.Context, req *pb.Request) (*pb.Response, error) {
//		claims, err := jwtgrpc.GetClaimsWithKey(ctx, "my-custom-key")
//		if err != nil {
//			return nil, status.Errorf(codes.Unauthenticated, "invalid auth: %v", err)
//		}
//		return &pb.Response{}, nil
//	}
func GetClaimsWithKey(ctx context.Context, key string) (*validator.ValidatedClaims, error) {
	return jwtmiddleware.GetClaimsWithKey(ctx, key)
}

// MustGetClaims returns validated claims from the gRPC context or returns an Unauthenticated error if not present.
// This is a convenience function for handlers that require valid claims.
//
// Example usage:
//
//	func (s *server) ProtectedMethod(ctx context.Context, req *pb.Request) (*pb.Response, error) {
//		claims, err := jwtgrpc.MustGetClaims(ctx)
//		if err != nil {
//			return nil, err // Error already formatted as gRPC error
//		}
//		// Use the claims...
//		return &pb.Response{Message: "Protected data for " + claims.RegisteredClaims.Subject}, nil
//	}
func MustGetClaims(ctx context.Context) (*validator.ValidatedClaims, error) {
	claims, err := GetClaims(ctx)
	if err != nil || claims == nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to get validated JWT claims: %v", err)
	}
	return claims, nil
}

// noopResponseWriter is an implementation of http.ResponseWriter that does nothing.
// It's used to adapt between the HTTP middleware and gRPC contexts.
type noopResponseWriter struct{}

func (n *noopResponseWriter) Header() http.Header        { return http.Header{} }
func (n *noopResponseWriter) Write([]byte) (int, error)  { return 0, nil }
func (n *noopResponseWriter) WriteHeader(statusCode int) {}

// defaultGRPCErrorHandler converts JWT authentication errors into appropriate gRPC errors.
// It preserves the error message but wraps it in a gRPC Unauthenticated error code.
func defaultGRPCErrorHandler(ctx context.Context, err error) error {
	return status.Errorf(codes.Unauthenticated, "unauthenticated: %v", err)
}

// wrappedServerStream is a wrapper around grpc.ServerStream that allows modifying
// the context returned by Context().
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the context for this stream, which contains the JWT claims
// when authentication succeeds.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
