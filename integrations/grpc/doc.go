// Package grpc provides gRPC server interceptors for JWT authentication.
//
// This package offers both unary and streaming interceptors that validate
// JWTs from gRPC metadata and make claims available in the request context.
//
// # Authentication
//
// This package supports Bearer token authentication (standard for gRPC).
//
// # Basic Usage
//
//	import (
//	    "context"
//	    "log"
//	    "net"
//
//	    jwtgrpc "github.com/auth0/go-jwt-middleware/v3/integrations/grpc"
//	    "github.com/auth0/go-jwt-middleware/v3/validator"
//	    "google.golang.org/grpc"
//	    "google.golang.org/grpc/codes"
//	    "google.golang.org/grpc/status"
//	)
//
//	func main() {
//	    // Create validator
//	    jwtValidator, err := validator.New(
//	        validator.WithKeyFunc(keyFunc),
//	        validator.WithAlgorithm(validator.RS256),
//	        validator.WithIssuer("https://issuer.example.com/"),
//	        validator.WithAudience("my-grpc-api"),
//	    )
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Create interceptor
//	    interceptor, err := jwtgrpc.New(
//	        jwtgrpc.WithValidator(jwtValidator),
//	    )
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Create gRPC server with interceptors
//	    server := grpc.NewServer(
//	        grpc.UnaryInterceptor(interceptor.UnaryServerInterceptor()),
//	        grpc.StreamInterceptor(interceptor.StreamServerInterceptor()),
//	    )
//
//	    // Register your services...
//	    // pb.RegisterYourServiceServer(server, &yourService{})
//
//	    // Start server
//	    listener, _ := net.Listen("tcp", ":50051")
//	    server.Serve(listener)
//	}
//
// # Advanced Configuration
//
// Combine multiple options for advanced features:
//
//	import "log/slog"
//
//	interceptor, err := jwtgrpc.New(
//	    jwtgrpc.WithValidator(jwtValidator),
//	    jwtgrpc.WithLogger(slog.Default()),
//	    jwtgrpc.WithCredentialsOptional(true),
//	    jwtgrpc.WithExcludedMethods("/grpc.health.v1.Health/Check"),
//	)
//
// # Features
//
//   - Unary and streaming interceptor support
//   - Token extraction from gRPC metadata
//   - Method exclusions for public endpoints
//   - Custom error handling with gRPC status codes
//   - Optional logging
//   - Type-safe claims retrieval with generics
//
// # Claims Retrieval
//
// After the interceptor validates the JWT, claims are available in the context.
// Use the provided helper functions to retrieve claims in a type-safe manner:
//
//	func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
//	    // Get claims from context
//	    claims, err := jwtgrpc.GetClaims[*validator.ValidatedClaims](ctx)
//	    if err != nil {
//	        return nil, status.Error(codes.Internal, "failed to get claims")
//	    }
//
//	    // Use claims
//	    userID := claims.RegisteredClaims.Subject
//
//	    // Your business logic...
//	    user := &pb.User{ID: userID}
//	    return user, nil
//	}
//
// Available helper functions:
//   - GetClaims[T](ctx) - Type-safe retrieval with error
//   - MustGetClaims[T](ctx) - Panics if claims not found (use with caution)
//   - HasClaims(ctx) - Check if claims exist
//
// See the examples directory for complete working examples.
package grpc
