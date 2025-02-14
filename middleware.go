package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"google.golang.org/grpc"
)

// ContextKey is the key used in the request
// context where the information from a
// validated JWT will be stored.
type ContextKey struct{}

type JWTMiddleware struct {
	validateToken       ValidateToken
	errorHandler        ErrorHandler
	tokenExtractor      TokenExtractor
	credentialsOptional bool
	validateOnOptions   bool
}

type GrpcMiddleware struct {
	validateToken       ValidateToken
	errorHandler        GrpcErrorHandler
	tokenExtractor      ContextTokenExtractor
	credentialsOptional bool
}

// ValidateToken takes in a string JWT and makes sure it is valid and
// returns the valid token. If it is not valid it will return nil and
// an error message describing why validation failed.
// Inside ValidateToken things like key and alg checking can happen.
// In the default implementation we can add safe defaults for those.
type ValidateToken func(context.Context, string) (interface{}, error)

// New constructs a new JWTMiddleware instance with the supplied options.
// It requires a ValidateToken function to be passed in, so it can
// properly validate tokens.
func New(validateToken ValidateToken, opts ...Option) *JWTMiddleware {
	m := &JWTMiddleware{
		validateToken:       validateToken,
		errorHandler:        DefaultErrorHandler,
		credentialsOptional: false,
		tokenExtractor:      AuthHeaderTokenExtractor,
		validateOnOptions:   true,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// NewGrpc constructs a new GrpcMiddleware instance with the supplied options.
// It requires a ValidateToken function to be passed in, so it can
// properly validate tokens.
// Default Unary and Stream error interceptors (handlers) are set if the corresponding options are not
// specified on opts
func NewGrpc(validateToken ValidateToken, opts ...GrpcOption) *GrpcMiddleware {
	m := &GrpcMiddleware{
		validateToken:       validateToken,
		errorHandler:        DefaultGrpcErrorHandler(),
		credentialsOptional: false,
		tokenExtractor:      GrpcTokenExtractor(),
	}

	for _, opt := range opts {
		opt(m)
	}

	if m.errorHandler.GrpcStreamErrorHandler == nil {
		m.errorHandler.GrpcStreamErrorHandler = DefaultGrpcStreamErrorHandler
	}
	if m.errorHandler.GrpcUnaryErrorHandler == nil {
		m.errorHandler.GrpcUnaryErrorHandler = DefaultGrpcUnaryErrorHandler
	}

	return m
}

// CheckJWT is the main JWTMiddleware function which performs the main logic. It
// is passed a http.Handler which will be called if the JWT passes validation.
func (m *JWTMiddleware) CheckJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If we don't validate on OPTIONS and this is OPTIONS
		// then continue onto next without validating.
		if !m.validateOnOptions && r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		token, err := m.tokenExtractor(r)
		if err != nil {
			// This is not ErrJWTMissing because an error here means that the
			// tokenExtractor had an error and _not_ that the token was missing.
			m.errorHandler(w, r, fmt.Errorf("error extracting token: %w", err))
			return
		}

		if token == "" {
			// If credentials are optional continue
			// onto next without validating.
			if m.credentialsOptional {
				next.ServeHTTP(w, r)
				return
			}

			// Credentials were not optional so we error.
			m.errorHandler(w, r, ErrJWTMissing)
			return
		}

		// Validate the token using the token validator.
		validToken, err := m.validateToken(r.Context(), token)
		if err != nil {
			m.errorHandler(w, r, &invalidError{details: err})
			return
		}

		// No err means we have a valid token, so set
		// it into the context and continue onto next.
		r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))
		next.ServeHTTP(w, r)
	})
}

// wrappedStream wraps around the embedded grpc.ServerStream, and intercepts the RecvMsg and
// SendMsg method call. ctx allows the context to be modified to add the jwt
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) RecvMsg(m any) error {
	return w.ServerStream.RecvMsg(m)
}

func (w *wrappedStream) SendMsg(m any) error {
	return w.ServerStream.SendMsg(m)
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}

func newWrappedStream(s grpc.ServerStream) grpc.ServerStream {
	return &wrappedStream{
		ServerStream: s,
		ctx:          s.Context(),
	}
}

func newWrappedStreamWithContext(s grpc.ServerStream, newContext context.Context) grpc.ServerStream {
	return &wrappedStream{
		ServerStream: s,
		ctx:          newContext,
	}
}

func (m *GrpcMiddleware) CheckJWT() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	return m.checkJWTUnary, m.checkJWTStream
}

func (m *GrpcMiddleware) checkJWTUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if currentJwt := ctx.Value(ContextKey{}); currentJwt != nil {
		return handler(ctx, req)
	}

	var (
		token      string
		err        error
		validToken any
	)
	switch token, err = m.tokenExtractor(ctx); {
	case err != nil:
		return m.errorHandler.GrpcUnaryErrorHandler(ctx, req, info, handler, err)
	case token == "" && m.credentialsOptional:
		return handler(ctx, req)
	case token == "":
		return m.errorHandler.GrpcUnaryErrorHandler(ctx, req, info, handler, ErrJWTMissing)
	default:
		switch validToken, err = m.validateToken(ctx, token); {
		case err != nil:
			return m.errorHandler.GrpcUnaryErrorHandler(ctx, req, info, handler, &invalidError{details: err})
		case validToken != nil:
			return handler(context.WithValue(ctx, ContextKey{}, validToken), req)
		default:
			return m.errorHandler.GrpcUnaryErrorHandler(ctx, req, info, handler, ErrJWTInvalid)
		}
	}
}

func (m *GrpcMiddleware) checkJWTStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	var (
		ctx        context.Context
		token      string
		err        error
		validToken any
	)
	if ss != nil {
		ctx = ss.Context()
		if currentJwt := ctx.Value(ContextKey{}); currentJwt != nil {
			return handler(srv, newWrappedStream(ss))
		}
	}
	token, err = m.tokenExtractor(ctx)
	switch {
	case err != nil:
		return m.errorHandler.GrpcStreamErrorHandler(srv, ss, info, handler, err)
	case token == "" && m.credentialsOptional:
		return handler(srv, newWrappedStream(ss))
	case token == "":
		return m.errorHandler.GrpcStreamErrorHandler(srv, ss, info, handler, ErrJWTMissing)
	default:
		switch validToken, err = m.validateToken(ctx, token); {
		case err != nil:
			return m.errorHandler.GrpcStreamErrorHandler(srv, ss, info, handler, &invalidError{details: err})
		case validToken != nil:
			ctx = context.WithValue(ctx, ContextKey{}, validToken)
			return handler(srv, newWrappedStreamWithContext(ss, ctx))
		default:
			return m.errorHandler.GrpcStreamErrorHandler(srv, ss, info, handler, ErrJWTInvalid)
		}
	}

}
