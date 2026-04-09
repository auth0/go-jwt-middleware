package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	jwtgrpc "github.com/auth0/go-jwt-middleware/v3/integrations/grpc"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	pb "github.com/auth0/go-jwt-middleware/v3/examples/grpc-example/proto"
)

// setupTestServer creates a test gRPC server with JWT authentication
func setupTestServer(t *testing.T) (*grpc.Server, net.Listener, pb.GreeterClient) {
	// Set up the JWT validator
	keyFunc := func(ctx context.Context) (any, error) {
		return signingKey, nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience),
	)
	require.NoError(t, err)

	// Create JWT interceptor with health check excluded
	jwtInterceptor, err := jwtgrpc.New(
		jwtgrpc.WithValidator(jwtValidator),
		jwtgrpc.WithExcludedMethods("/greeter.Greeter/HealthCheck"),
	)
	require.NoError(t, err)

	// Create gRPC server with JWT interceptors
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(jwtInterceptor.UnaryServerInterceptor()),
		grpc.StreamInterceptor(jwtInterceptor.StreamServerInterceptor()),
	)

	// Register the Greeter service
	pb.RegisterGreeterServer(grpcServer, &server{})

	// Start listening on random port
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	// Start server in background
	go func() {
		_ = grpcServer.Serve(lis)
	}()

	// Create client connection
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.Close()
		grpcServer.Stop()
	})

	client := pb.NewGreeterClient(conn)
	return grpcServer, lis, client
}

// generateToken creates a JWT token for testing
func generateToken(t *testing.T, subject string, customClaims map[string]interface{}) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}

	// Add custom claims
	for k, v := range customClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(signingKey)
	require.NoError(t, err)
	return tokenString
}

func TestGRPCExample_ValidToken(t *testing.T) {
	_, _, client := setupTestServer(t)

	// Generate valid token
	token := generateToken(t, "user123", map[string]interface{}{
		"name": "John Doe",
	})

	// Create context with authorization metadata
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Call SayHello
	resp, err := client.SayHello(ctx, &pb.HelloRequest{Name: "World"})
	require.NoError(t, err)
	assert.Equal(t, "Hello World!", resp.Message)
	assert.Equal(t, "user123", resp.AuthenticatedAs)
}

func TestGRPCExample_MissingToken(t *testing.T) {
	_, _, client := setupTestServer(t)

	// Call SayHello without token
	ctx := context.Background()
	_, err := client.SayHello(ctx, &pb.HelloRequest{Name: "World"})

	// Should be unauthenticated
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGRPCExample_InvalidToken(t *testing.T) {
	_, _, client := setupTestServer(t)

	// Create context with invalid token
	md := metadata.Pairs("authorization", "Bearer invalid.token.here")
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Call SayHello
	_, err := client.SayHello(ctx, &pb.HelloRequest{Name: "World"})

	// Should be unauthenticated
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGRPCExample_WrongIssuer(t *testing.T) {
	_, _, client := setupTestServer(t)

	// Generate token with wrong issuer
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "wrong-issuer",
		"aud": audience,
		"sub": "user123",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(signingKey)
	require.NoError(t, err)

	// Create context with token
	md := metadata.Pairs("authorization", "Bearer "+tokenString)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Call SayHello
	_, err = client.SayHello(ctx, &pb.HelloRequest{Name: "World"})

	// Should be unauthenticated
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGRPCExample_WrongAudience(t *testing.T) {
	_, _, client := setupTestServer(t)

	// Generate token with wrong audience
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"aud": []string{"wrong-audience"},
		"sub": "user123",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(signingKey)
	require.NoError(t, err)

	// Create context with token
	md := metadata.Pairs("authorization", "Bearer "+tokenString)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Call SayHello
	_, err = client.SayHello(ctx, &pb.HelloRequest{Name: "World"})

	// Should be unauthenticated
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGRPCExample_ExpiredToken(t *testing.T) {
	_, _, client := setupTestServer(t)

	// Generate expired token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "user123",
		"iat": now.Add(-2 * time.Hour).Unix(),
		"exp": now.Add(-time.Hour).Unix(), // Expired 1 hour ago
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(signingKey)
	require.NoError(t, err)

	// Create context with token
	md := metadata.Pairs("authorization", "Bearer "+tokenString)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Call SayHello
	_, err = client.SayHello(ctx, &pb.HelloRequest{Name: "World"})

	// Should be unauthenticated
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGRPCExample_HealthCheckNoAuth(t *testing.T) {
	_, _, client := setupTestServer(t)

	// Call HealthCheck without token (should work - excluded method)
	ctx := context.Background()
	resp, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
}

func TestGRPCExample_HealthCheckWithAuth(t *testing.T) {
	_, _, client := setupTestServer(t)

	// Generate valid token
	token := generateToken(t, "user123", nil)

	// Create context with authorization metadata
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Call HealthCheck with token (should also work)
	resp, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
}

func TestGRPCExample_MalformedAuthHeader(t *testing.T) {
	_, _, client := setupTestServer(t)

	testCases := []struct {
		name   string
		header string
	}{
		{
			name:   "missing Bearer prefix",
			header: "just-a-token",
		},
		{
			name:   "wrong scheme",
			header: "Basic dXNlcjpwYXNz",
		},
		{
			name:   "empty value",
			header: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", tc.header)
			ctx := metadata.NewOutgoingContext(context.Background(), md)

			_, err := client.SayHello(ctx, &pb.HelloRequest{Name: "World"})
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			// Malformed auth headers return InvalidArgument
			assert.Equal(t, codes.InvalidArgument, st.Code())
		})
	}
}
