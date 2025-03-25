package grpcjwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrMissingClaims = errors.New("no JWT claims found in context")
	ErrInvalidClaims = errors.New("invalid JWT claims type")
)

// JWTInterceptor provides configurable JWT authentication for gRPC.
type JWTInterceptor struct {
	validateToken       jwtmiddleware.ValidateToken
	tokenExtractor      GRPCTokenExtractor
	credentialsOptional bool
	exclusionChecker    ExclusionChecker
	logger              Logger
	metricsRecorder     MetricsRecorder
	tracer              Tracer
}

// New creates a new JWTInterceptor with the given options.
func New(validateToken jwtmiddleware.ValidateToken, opts ...Option) *JWTInterceptor {
	i := &JWTInterceptor{
		validateToken:       validateToken,
		tokenExtractor:      MetadataTokenExtractor,
		credentialsOptional: false,
		logger:              &NoopLogger{},
		metricsRecorder:     &NoopMetricsRecorder{},
		tracer:              &NoopTracer{},
	}

	for _, opt := range opts {
		opt(i)
	}

	return i
}

// authenticate handles token extraction, validation, and context updating.
// It returns the new context with validated claims or an error.
// The caller is responsible for managing the tracing span.
func (i *JWTInterceptor) authenticate(ctx context.Context, method string) (context.Context, error) {
	start := time.Now()
	i.logger.Debug("Authenticating request", "method", method, "timestamp", start.Format(time.RFC3339))

	// Start tracing span
	spanCtx, span := i.tracer.StartSpan(ctx, method)

	// Check if the method is excluded from JWT validation
	if i.exclusionChecker != nil && i.exclusionChecker(method) {
		i.logger.Debug("Method excluded from JWT validation", "method", method)
		i.tracer.AddAttribute(span, "auth_status", "excluded")
		return spanCtx, nil
	}

	// Extract token from metadata
	token, err := i.tokenExtractor(ctx)
	if err != nil {
		i.logger.Error("Error extracting token", "method", method, "error", err.Error())
		i.metricsRecorder.IncAuthFailure(method, "extraction_error")
		i.tracer.AddAttribute(span, "auth_status", "extraction_error")
		return nil, status.Errorf(codes.Unauthenticated, "error extracting token: %v", err)
	}

	if token == "" {
		if i.credentialsOptional {
			i.logger.Debug("No token provided but credentials optional", "method", method)
			i.tracer.AddAttribute(span, "auth_status", "optional_no_token")
			return spanCtx, nil
		}
		i.logger.Error("JWT token is missing", "method", method)
		i.metricsRecorder.IncAuthFailure(method, "missing_token")
		i.tracer.AddAttribute(span, "auth_status", "missing_token")
		return nil, status.Errorf(codes.Unauthenticated, "JWT token is missing")
	}

	// Validate token
	validToken, err := i.validateToken(ctx, token)
	if err != nil {
		i.logger.Error("Invalid JWT token", "method", method, "error", err.Error())
		i.metricsRecorder.IncAuthFailure(method, "invalid_token")
		i.tracer.AddAttribute(span, "auth_status", "invalid_token")
		return nil, status.Errorf(codes.Unauthenticated, "invalid JWT token: %v", err)
	}

	// Record successful authentication
	i.logger.Info("JWT token validated successfully", "method", method)
	i.metricsRecorder.IncAuthSuccess(method)
	i.tracer.AddAttribute(span, "auth_status", "success")

	// Record authentication latency
	authDuration := time.Since(start)
	i.metricsRecorder.ObserveAuthLatency(method, authDuration)
	i.tracer.AddAttribute(span, "auth_duration_ms", fmt.Sprintf("%d", authDuration.Milliseconds()))

	// Add validated token to context
	newCtx := context.WithValue(spanCtx, jwtmiddleware.ContextKey{}, validToken)
	return newCtx, nil
}

// UnaryServerInterceptor returns a gRPC unary server interceptor for JWT authentication.
func (i *JWTInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Start tracing span for the entire request
		spanCtx, span := i.tracer.StartSpan(ctx, info.FullMethod)
		defer func() {
			i.tracer.FinishSpan(span, nil)
		}()

		// Authenticate and get the new context
		authCtx, err := i.authenticate(spanCtx, info.FullMethod)
		if err != nil {
			i.tracer.AddAttribute(span, "error", err.Error())
			return nil, err
		}

		// Call the handler with the authenticated context
		resp, err := handler(authCtx, req)
		if err != nil {
			i.tracer.AddAttribute(span, "error", err.Error())
		}
		return resp, err
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor for JWT authentication.
func (i *JWTInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		// Start tracing span for the entire stream
		spanCtx, span := i.tracer.StartSpan(ctx, info.FullMethod)
		defer func() {
			i.tracer.FinishSpan(span, nil)
		}()

		// Authenticate and get the new context
		authCtx, err := i.authenticate(spanCtx, info.FullMethod)
		if err != nil {
			i.tracer.AddAttribute(span, "error", err.Error())
			return err
		}

		// Wrap the server stream with the authenticated context
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          authCtx,
		}

		// Call the handler with the wrapped stream
		err = handler(srv, wrappedStream)
		if err != nil {
			i.tracer.AddAttribute(span, "error", err.Error())
		}
		return err
	}
}

// wrappedServerStream wraps a grpc.ServerStream to override the context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// GetClaimsFromContext retrieves the validated claims from the context.
// Returns nil if no claims are present.
func GetClaimsFromContext(ctx context.Context) *validator.ValidatedClaims {
	claims := ctx.Value(jwtmiddleware.ContextKey{})
	validatedClaims, ok := claims.(*validator.ValidatedClaims)
	if !ok {
		return nil
	}
	return validatedClaims
}

// RequireClaimsFromContext retrieves the validated claims from the context.
// Returns ErrMissingClaims if no claims are present, or ErrInvalidClaims if the claims are of an invalid type.
func RequireClaimsFromContext(ctx context.Context) (*validator.ValidatedClaims, error) {
	claims := ctx.Value(jwtmiddleware.ContextKey{})
	if claims == nil {
		return nil, ErrMissingClaims
	}
	validatedClaims, ok := claims.(*validator.ValidatedClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}
	return validatedClaims, nil
}
