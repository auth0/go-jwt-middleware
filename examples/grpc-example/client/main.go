package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/auth0/go-jwt-middleware/v3/examples/grpc-example/proto"
)

var (
	signingKey = []byte("secret")
	issuer     = "go-jwt-middleware-grpc-example"
	audience   = []string{"grpc-example"}
	serverAddr = "localhost:50051"
)

// generateToken creates a test JWT token
func generateToken(subject string) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

func main() {
	// Connect to the server
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewGreeterClient(conn)

	// Test 1: Health check (no auth required)
	fmt.Println("=== Test 1: Health Check (no authentication) ===")
	ctx := context.Background()
	healthResp, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{})
	if err != nil {
		log.Fatalf("Health check failed: %v", err)
	}
	fmt.Printf("Health check status: %s\n\n", healthResp.Status)

	// Test 2: SayHello without token (should fail)
	fmt.Println("=== Test 2: SayHello without authentication (should fail) ===")
	_, err = client.SayHello(ctx, &pb.HelloRequest{Name: "World"})
	if err != nil {
		fmt.Printf("Expected error: %v\n\n", err)
	} else {
		fmt.Println("ERROR: Should have failed without token!\n")
	}

	// Test 3: SayHello with valid token (should succeed)
	fmt.Println("=== Test 3: SayHello with valid JWT ===")
	token, err := generateToken("user123")
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	// Add JWT to metadata
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + token,
	})
	ctxWithAuth := metadata.NewOutgoingContext(context.Background(), md)

	helloResp, err := client.SayHello(ctxWithAuth, &pb.HelloRequest{Name: "World"})
	if err != nil {
		log.Fatalf("SayHello failed: %v", err)
	}
	fmt.Printf("Response: %s\n", helloResp.Message)
	fmt.Printf("Authenticated as: %s\n\n", helloResp.AuthenticatedAs)

	// Test 4: Multiple requests with same token
	fmt.Println("=== Test 4: Multiple authenticated requests ===")
	names := []string{"Alice", "Bob", "Charlie"}
	for _, name := range names {
		resp, err := client.SayHello(ctxWithAuth, &pb.HelloRequest{Name: name})
		if err != nil {
			log.Printf("Request failed for %s: %v", name, err)
			continue
		}
		fmt.Printf("%s (authenticated as: %s)\n", resp.Message, resp.AuthenticatedAs)
	}

	fmt.Println("\n=== All tests completed ===")
}
