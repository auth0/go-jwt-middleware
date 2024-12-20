package main

import (
	"context"
	"fmt"
	"github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"google.golang.org/grpc"
	"log"
	"net"
)

// Try it out with:
//
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.DSY4NlpZZ2mOqaKuXvJkOrgZA3nD5HuGaf1wB9-0OVw
//
// which is signed with 'abcdefghijklmnopqrstuvwxyz012345' and has the data:
//
//	{
//	  "iss": "go-jwt-middleware-example",
//	  "aud": "audience-example",
//	  "sub": "1234567890",
//	  "name": "John Doe",
//	  "iat": 1516239022,
//	  "username": "user123"
//	}

type server struct{}

func (s *server) DoSomething(ctx context.Context, req *ExampleMessage) (*ExampleMessage, error) {
	if currentJwt := ctx.Value(jwtmiddleware.ContextKey{}); currentJwt == nil || currentJwt.(*validator.ValidatedClaims) == nil {
		return nil, fmt.Errorf("%s", "did not find a valid token")
	}
	return &ExampleMessage{
		Msg: fmt.Sprintf("%s %s", req.Msg, "red fish, blue fish."),
	}, nil
}

func (s *server) mustEmbedUnimplementedExampleServiceServer() {}

func main() {
	s := createServer()
	log.Default().Println("Server is starting...")
	lis, _ := net.Listen("tcp", ":8080")
	if err := s.Serve(lis); err != nil {
		log.Default().Panic(err)
	}
	log.Default().Println("Server is exiting...")
}

func createServer() *grpc.Server {
	var (
		issuer       = "go-jwt-middleware-example"
		audience     = "audience-example"
		jwtValidator *validator.Validator
		err          error
	)
	secret := []byte("abcdefghijklmnopqrstuvwxyz012345")
	keyFunc := func(context.Context) (interface{}, error) {
		return secret, nil
	}

	if jwtValidator, err = validator.New(keyFunc, validator.HS256, issuer, []string{audience}); err != nil {
		panic(err)
	}
	ui, _ := jwtmiddleware.NewGrpc(jwtValidator.ValidateToken).CheckJWT()
	s := grpc.NewServer(
		grpc.ChainUnaryInterceptor(ui),
	)
	RegisterExampleServiceServer(s, &server{})

	return s
}
