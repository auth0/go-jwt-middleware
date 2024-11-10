package main

import (
	"context"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"log"
	"net"
	"testing"

	"github.com/auth0/go-jwt-middleware/v2"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func init() {
	var (
		issuer       = "testIssuer"
		audience     = "testAudience"
		jwtValidator *validator.Validator
		err          error
	)
	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
	}

	if jwtValidator, err = validator.New(keyFunc, validator.HS256, issuer, []string{audience}); err != nil {
		panic(err)
	}

	lis = bufconn.Listen(bufSize)
	ui, _ := jwtmiddleware.NewGrpc(jwtValidator.ValidateToken).CheckJWT()
	s := grpc.NewServer(grpc.ChainUnaryInterceptor(ui))
	RegisterExampleServiceServer(s, &server{})
	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
}

func TestDoSomething(t *testing.T) {
	var (
		ctx        = context.Background()
		validToken = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwiYXVkIjoidGVzdEF1ZGllbmNlIn0.7pJ1SzeMusdScckEdTgyNSbdPw8HQWLdSv9ZGQrSAHE"
	)
	conn, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", validToken)
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
	)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	client := NewExampleServiceClient(conn)
	resp, err := client.DoSomething(ctx, &ExampleMessage{Msg: "one fish, two fish."})
	require.NoError(t, err)
	log.Printf("Response: %s\n", resp.Msg)
}

func TestDoSomething_InvalidToken(t *testing.T) {
	var (
		ctx          = context.Background()
		invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0aW5nIn0.eM1Jd7VA7nFSI09FlmLmtuv7cLnv8qicZ8s76-jTOoE"
	)
	conn, err := grpc.NewClient(
		"passthrough://bufnet",
		//grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", invalidToken)
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
	)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	client := NewExampleServiceClient(conn)
	_, err = client.DoSomething(ctx, &ExampleMessage{Msg: "one fish, two fish."})
	require.Error(t, err)
	if s, ok := status.FromError(err); ok {
		assert.EqualError(t, s.Err(), status.Errorf(codes.Unauthenticated, jwtmiddleware.ErrJWTInvalid.Error()).Error())
	}
}
