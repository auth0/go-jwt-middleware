package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

const (
	issuer   = "testIssuer"
	audience = "testAudience"
)

// buildTestToken generates a valid JWT for testing using jwx/v3
func buildTestToken(t *testing.T, iss, aud string) string {
	t.Helper()

	// Build JWT token
	now := time.Now()
	token := jwt.New()
	require.NoError(t, token.Set(jwt.IssuerKey, iss))
	require.NoError(t, token.Set(jwt.AudienceKey, []string{aud}))
	require.NoError(t, token.Set(jwt.IssuedAtKey, now))
	require.NoError(t, token.Set(jwt.ExpirationKey, now.Add(24*time.Hour)))

	// Sign the token using the shared test key
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), testJWK))
	require.NoError(t, err, "could not sign token")

	return string(signed)
}

// testPrivateKey is shared across tests for token signing
var testPrivateKey *ecdsa.PrivateKey
var testJWK jwk.Key

func init() {
	var err error
	testPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	testJWK, err = jwk.Import(testPrivateKey)
	if err != nil {
		panic(err)
	}
}

func createTestValidator(t *testing.T) *validator.Validator {
	keyFunc := func(context.Context) (any, error) {
		return &testPrivateKey.PublicKey, nil
	}

	v, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.ES256),
		validator.WithIssuer(issuer),
		validator.WithAudience(audience),
	)
	require.NoError(t, err)
	return v
}

func TestUnaryServerInterceptor_Success(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		claims := MustGetClaims[*validator.ValidatedClaims](ctx)
		assert.NotNil(t, claims)
		assert.Equal(t, issuer, claims.RegisteredClaims.Issuer)
		return "success", nil
	}

	md := metadata.Pairs("authorization", "Bearer "+buildTestToken(t, issuer, audience))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}

func TestUnaryServerInterceptor_MissingToken(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	ctx := context.Background()

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.Nil(t, resp)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestUnaryServerInterceptor_InvalidToken(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	invalidToken := buildTestToken(t, "wrongIssuer", audience)
	md := metadata.Pairs("authorization", "Bearer "+invalidToken)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.Nil(t, resp)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestUnaryServerInterceptor_InvalidFormat(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	md := metadata.Pairs("authorization", "InvalidFormat")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.Nil(t, resp)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestUnaryServerInterceptor_MultipleAuthHeaders(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	md := metadata.Pairs(
		"authorization", "Bearer "+buildTestToken(t, issuer, audience),
		"authorization", "Bearer "+buildTestToken(t, issuer, audience),
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.Nil(t, resp)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestUnaryServerInterceptor_OptionalCredentials_NoToken(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v), WithCredentialsOptional(true))
	require.NoError(t, err)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		assert.False(t, HasClaims(ctx))
		return "success", nil
	}

	ctx := context.Background()

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
	assert.True(t, handlerCalled)
}

func TestUnaryServerInterceptor_OptionalCredentials_WithToken(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v), WithCredentialsOptional(true))
	require.NoError(t, err)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		assert.True(t, HasClaims(ctx))
		claims := MustGetClaims[*validator.ValidatedClaims](ctx)
		assert.Equal(t, issuer, claims.RegisteredClaims.Issuer)
		return "success", nil
	}

	md := metadata.Pairs("authorization", "Bearer "+buildTestToken(t, issuer, audience))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
	assert.True(t, handlerCalled)
}

func TestUnaryServerInterceptor_ExcludedMethods(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v), WithExcludedMethods("/test.Service/HealthCheck"))
	require.NoError(t, err)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		assert.False(t, HasClaims(ctx))
		return "success", nil
	}

	ctx := context.Background()

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/HealthCheck"}, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
	assert.True(t, handlerCalled)
}

func TestUnaryServerInterceptor_ValidatorError(t *testing.T) {
	keyFunc := func(context.Context) (any, error) {
		return nil, errors.New("JWKS fetch failed")
	}

	v, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudience(audience),
	)
	require.NoError(t, err)

	interceptor, err := New(WithValidator(v))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	md := metadata.Pairs("authorization", "Bearer "+buildTestToken(t, issuer, audience))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.Nil(t, resp)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	// JWKS fetch errors should be Internal (server-side infrastructure error)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestStreamServerInterceptor_Success(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v))
	require.NoError(t, err)

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		ctx := stream.Context()
		assert.True(t, HasClaims(ctx))
		claims := MustGetClaims[*validator.ValidatedClaims](ctx)
		assert.Equal(t, issuer, claims.RegisteredClaims.Issuer)
		return nil
	}

	md := metadata.Pairs("authorization", "Bearer "+buildTestToken(t, issuer, audience))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	mockStream := &mockServerStream{ctx: ctx}

	err = interceptor.StreamServerInterceptor()(nil, mockStream, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, handler)

	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestStreamServerInterceptor_MissingToken(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v))
	require.NoError(t, err)

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		t.Fatal("handler should not be called")
		return nil
	}

	mockStream := &mockServerStream{ctx: context.Background()}

	err = interceptor.StreamServerInterceptor()(nil, mockStream, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, handler)

	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestStreamServerInterceptor_OptionalCredentials(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v), WithCredentialsOptional(true))
	require.NoError(t, err)

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		ctx := stream.Context()
		assert.False(t, HasClaims(ctx))
		return nil
	}

	mockStream := &mockServerStream{ctx: context.Background()}

	err = interceptor.StreamServerInterceptor()(nil, mockStream, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, handler)

	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestStreamServerInterceptor_ExcludedMethods(t *testing.T) {
	v := createTestValidator(t)
	interceptor, err := New(WithValidator(v), WithExcludedMethods("/test.Service/HealthStream"))
	require.NoError(t, err)

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		ctx := stream.Context()
		assert.False(t, HasClaims(ctx))
		return nil
	}

	mockStream := &mockServerStream{ctx: context.Background()}

	err = interceptor.StreamServerInterceptor()(nil, mockStream, &grpc.StreamServerInfo{FullMethod: "/test.Service/HealthStream"}, handler)

	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestGetClaims_Success(t *testing.T) {
	tokenClaims := &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{
			Issuer:   issuer,
			Audience: []string{audience},
		},
	}

	ctx := core.SetClaims(context.Background(), tokenClaims)

	claims, err := GetClaims[*validator.ValidatedClaims](ctx)
	assert.NoError(t, err)
	assert.Equal(t, issuer, claims.RegisteredClaims.Issuer)
}

func TestGetClaims_NotFound(t *testing.T) {
	ctx := context.Background()

	claims, err := GetClaims[*validator.ValidatedClaims](ctx)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestMustGetClaims_Success(t *testing.T) {
	tokenClaims := &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{
			Issuer:   issuer,
			Audience: []string{audience},
		},
	}

	ctx := core.SetClaims(context.Background(), tokenClaims)

	claims := MustGetClaims[*validator.ValidatedClaims](ctx)
	assert.Equal(t, issuer, claims.RegisteredClaims.Issuer)
}

func TestMustGetClaims_Panic(t *testing.T) {
	ctx := context.Background()

	assert.Panics(t, func() {
		MustGetClaims[*validator.ValidatedClaims](ctx)
	})
}

func TestHasClaims(t *testing.T) {
	tokenClaims := &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{
			Issuer: issuer,
		},
	}

	ctxWithClaims := core.SetClaims(context.Background(), tokenClaims)
	assert.True(t, HasClaims(ctxWithClaims))

	ctxWithoutClaims := context.Background()
	assert.False(t, HasClaims(ctxWithoutClaims))
}

func TestCustomErrorHandler(t *testing.T) {
	v := createTestValidator(t)

	customErrorCalled := false
	customErrorHandler := func(err error) error {
		customErrorCalled = true
		return status.Error(codes.PermissionDenied, "custom error")
	}

	interceptor, err := New(WithValidator(v), WithErrorHandler(customErrorHandler))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	ctx := context.Background()

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.True(t, customErrorCalled)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Equal(t, "custom error", st.Message())
}

func TestCustomTokenExtractor(t *testing.T) {
	v := createTestValidator(t)
	validToken := buildTestToken(t, issuer, audience)

	customExtractorCalled := false
	customExtractor := func(ctx context.Context) (string, error) {
		customExtractorCalled = true
		return validToken, nil
	}

	interceptor, err := New(WithValidator(v), WithTokenExtractor(customExtractor))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		claims := MustGetClaims[*validator.ValidatedClaims](ctx)
		assert.NotNil(t, claims)
		return "success", nil
	}

	ctx := context.Background()

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
	assert.True(t, customExtractorCalled)
}

func TestCustomTokenExtractor_Error(t *testing.T) {
	v := createTestValidator(t)

	customExtractor := func(ctx context.Context) (string, error) {
		return "", errors.New("custom extraction error")
	}

	interceptor, err := New(WithValidator(v), WithTokenExtractor(customExtractor))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	ctx := context.Background()

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.Nil(t, resp)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	// Custom extractor errors are treated as generic errors, mapped to Unauthenticated
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestWithLogger(t *testing.T) {
	v := createTestValidator(t)

	logCalled := false
	logger := &mockLogger{
		onDebug: func(msg string, args ...any) { logCalled = true },
	}

	interceptor, err := New(WithValidator(v), WithLogger(logger))
	require.NoError(t, err)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "success", nil
	}

	md := metadata.Pairs("authorization", "Bearer "+buildTestToken(t, issuer, audience))
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
	assert.True(t, logCalled)
}



// mockLogger implements Logger interface for testing
type mockLogger struct {
	onDebug func(msg string, args ...any)
	onInfo  func(msg string, args ...any)
	onWarn  func(msg string, args ...any)
	onError func(msg string, args ...any)
}

func (m *mockLogger) Debug(msg string, args ...any) {
	if m.onDebug != nil {
		m.onDebug(msg, args...)
	}
}

func (m *mockLogger) Info(msg string, args ...any) {
	if m.onInfo != nil {
		m.onInfo(msg, args...)
	}
}

func (m *mockLogger) Warn(msg string, args ...any) {
	if m.onWarn != nil {
		m.onWarn(msg, args...)
	}
}

func (m *mockLogger) Error(msg string, args ...any) {
	if m.onError != nil {
		m.onError(msg, args...)
	}
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockServerStream) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockServerStream) SetTrailer(metadata.MD) {
}

func (m *mockServerStream) SendMsg(interface{}) error {
	return nil
}

func (m *mockServerStream) RecvMsg(interface{}) error {
	return nil
}
