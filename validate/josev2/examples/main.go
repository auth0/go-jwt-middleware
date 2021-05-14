package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/auth0/go-jwt-middleware/validate/josev2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// CustomClaimsExample contains custom data we want from the token.
type CustomClaimsExample struct {
	Username     string `json:"username"`
	ShouldReject bool   `json:"shouldReject,omitempty"`
}

// Validate does nothing for this example
func (c *CustomClaimsExample) Validate(ctx context.Context) error {
	if c.ShouldReject {
		return errors.New("should reject was set to true")
	}
	return nil
}

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user")
	j, err := json.MarshalIndent(user, "", "\t")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
	}

	fmt.Fprintf(w, "This is an authenticated request")
	fmt.Fprintf(w, "Claim content:\n")
	fmt.Fprint(w, string(j))
})

func main() {
	keyFunc := func(ctx context.Context) (interface{}, error) {
		// our token must be signed using this data
		return []byte("secret"), nil
	}
	expectedClaims := func() jwt.Expected {
		// By setting up expected claims we are saying a token must
		// have the data we specify.
		return jwt.Expected{
			Issuer: "josev2-example",
			Time:   time.Now(),
		}
	}
	customClaims := func() josev2.CustomClaims {
		// we want this struct to be filled in with our custom claims
		// from the token
		return &CustomClaimsExample{}
	}

	// setup the josev2 validator
	validator, err := josev2.New(
		keyFunc,
		jose.HS256,
		josev2.WithExpectedClaims(expectedClaims),
		josev2.WithCustomClaims(customClaims),
		josev2.WithAllowedClockSkew(30*time.Second),
	)

	if err != nil {
		// we'll panic in order to fail fast
		panic(err)
	}

	// setup the middleware
	m := jwtmiddleware.New(jwtmiddleware.WithValidateToken(validator.ValidateToken))

	http.ListenAndServe("0.0.0.0:3000", m.CheckJWT(handler))
	// try it out with eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb3NldjItZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.1v7S4aF7lVM92bRZ8tVTrKGZ6FwkX-7ybZQA5A7mq8E
	// which is signed with 'secret' and has the data:
	// {
	//   "iss": "josev2-example",
	//   "sub": "1234567890",
	//   "name": "John Doe",
	//   "iat": 1516239022,
	//   "username": "user123"
	// }
}
