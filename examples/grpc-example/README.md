# gRPC JWT Authentication Example

This example demonstrates how to use the `go-jwt-middleware` with gRPC services.

## Features Demonstrated

- JWT authentication for gRPC unary methods
- Excluding specific methods from authentication (health checks)
- Retrieving validated claims in gRPC handlers
- Client-side token attachment using metadata

## Structure

- `proto/` - Protocol Buffer definitions
- `server/` - gRPC server with JWT middleware
- `client/` - Test client that makes authenticated requests

## Running the Example

### Prerequisites

```bash
# Install dependencies
cd examples/grpc-example
go mod download
```

### Start the Server

In one terminal:

```bash
go run server/main.go
```

The server will start on port 50051 with:
- `/greeter.Greeter/SayHello` - Requires JWT authentication
- `/greeter.Greeter/HealthCheck` - Public endpoint (no auth)

### Run the Client

In another terminal:

```bash
go run client/main.go
```

The client will:
1. Call HealthCheck (no authentication)
2. Try to call SayHello without a token (fails)
3. Call SayHello with a valid JWT token (succeeds)
4. Make multiple authenticated requests

## Expected Output

### Server
```
gRPC server listening on :50051
- /greeter.Greeter/SayHello requires JWT authentication
- /greeter.Greeter/HealthCheck is public
```

### Client
```
=== Test 1: Health Check (no authentication) ===
Health check status: healthy

=== Test 2: SayHello without authentication (should fail) ===
Expected error: rpc error: code = Unauthenticated desc = missing credentials

=== Test 3: SayHello with valid JWT ===
Response: Hello World!
Authenticated as: user123

=== Test 4: Multiple authenticated requests ===
Hello Alice! (authenticated as: user123)
Hello Bob! (authenticated as: user123)
Hello Charlie! (authenticated as: user123)

=== All tests completed ===
```

## Key Code Snippets

### Server Setup

```go
// Create validator
jwtValidator, _ := validator.New(
    validator.WithKeyFunc(keyFunc),
    validator.WithAlgorithm(validator.HS256),
    validator.WithIssuer(issuer),
    validator.WithAudiences(audience),
)

// Create interceptor with excluded methods
jwtInterceptor, _ := jwtgrpc.New(
    jwtgrpc.WithValidator(jwtValidator),
    jwtgrpc.WithExcludedMethods("/greeter.Greeter/HealthCheck"),
)

// Add to gRPC server
grpcServer := grpc.NewServer(
    grpc.UnaryInterceptor(jwtInterceptor.UnaryServerInterceptor()),
    grpc.StreamInterceptor(jwtInterceptor.StreamServerInterceptor()),
)
```

### Handler with Claims

```go
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
    // Get validated claims
    claims, err := jwtgrpc.GetClaims[*validator.ValidatedClaims](ctx)
    if err != nil {
        return nil, status.Error(codes.Internal, "failed to get claims")
    }
    
    // Use claims data
    subject := claims.RegisteredClaims.Subject
    // ...
}
```

### Client with JWT

```go
// Add JWT to metadata
md := metadata.New(map[string]string{
    "authorization": "Bearer " + token,
})
ctx := metadata.NewOutgoingContext(context.Background(), md)

// Make authenticated call
resp, err := client.SayHello(ctx, &pb.HelloRequest{Name: "World"})
```

## Configuration Options

The interceptor supports several configuration options:

- `WithValidator()` - Set the JWT validator (required)
- `WithCredentialsOptional()` - Allow requests without tokens
- `WithExcludedMethods()` - Skip auth for specific methods
- `WithErrorHandler()` - Custom error handling
- `WithLogger()` - Add logging

See the [gRPC integration documentation](../../integrations/grpc/doc.go) for more details.
