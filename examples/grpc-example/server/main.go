package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	jwtgrpc "github.com/auth0/go-jwt-middleware/v3/integrations/grpc"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	pb "github.com/auth0/go-jwt-middleware/v3/examples/grpc-example/proto"
)

var (
	signingKey = []byte("secret")
	issuer     = "go-jwt-middleware-grpc-example"
	audience   = []string{"grpc-example"}
	port       = ":50051"
)

// server implements the Greeter service.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello returns a greeting. Requires authentication.
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	// Retrieve validated JWT claims from context
	claims, err := jwtgrpc.GetClaims[*validator.ValidatedClaims](ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get claims")
	}

	// Use the subject from the JWT
	authenticatedAs := claims.RegisteredClaims.Subject
	if authenticatedAs == "" {
		authenticatedAs = "anonymous"
	}

	message := fmt.Sprintf("Hello %s!", in.GetName())
	return &pb.HelloReply{
		Message:         message,
		AuthenticatedAs: authenticatedAs,
	}, nil
}

// HealthCheck returns server status. No authentication required.
func (s *server) HealthCheck(ctx context.Context, in *pb.HealthCheckRequest) (*pb.HealthCheckReply, error) {
	return &pb.HealthCheckReply{Status: "healthy"}, nil
}

func main() {
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
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}

	// Create JWT interceptor with health check excluded
	jwtInterceptor, err := jwtgrpc.New(
		jwtgrpc.WithValidator(jwtValidator),
		jwtgrpc.WithExcludedMethods("/greeter.Greeter/HealthCheck"),
	)
	if err != nil {
		log.Fatalf("Failed to create JWT interceptor: %v", err)
	}

	// Create gRPC server with JWT interceptors
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(jwtInterceptor.UnaryServerInterceptor()),
		grpc.StreamInterceptor(jwtInterceptor.StreamServerInterceptor()),
	)

	// Register the Greeter service
	pb.RegisterGreeterServer(grpcServer, &server{})

	// Start listening
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("gRPC server listening on %s", port)
	log.Printf("- /greeter.Greeter/SayHello requires JWT authentication")
	log.Printf("- /greeter.Greeter/HealthCheck is public")
	
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
