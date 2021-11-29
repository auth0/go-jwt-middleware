package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/auth0/go-jwt-middleware"
	"github.com/auth0/go-jwt-middleware/validate/josev2"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*josev2.UserContext)

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

// CustomClaimsExample contains custom data we want from the token.
type CustomClaimsExample struct {
	Name         string `json:"name"`
	Username     string `json:"username"`
	ShouldReject bool   `json:"shouldReject,omitempty"`
}

// Validate does nothing for this example.
func (c *CustomClaimsExample) Validate(ctx context.Context) error {
	if c.ShouldReject {
		return errors.New("should reject was set to true")
	}
	return nil
}

func main() {
	keyFunc := func(ctx context.Context) (interface{}, error) {
		// Our token must be signed using this data.
		return []byte("secret"), nil
	}

	// We want this struct to be filled in with
	// our custom claims from the token.
	customClaims := &CustomClaimsExample{}

	// Set up the josev2 validator.
	validator, err := josev2.New(
		keyFunc,
		"HS256",
		"josev2-example",
		[]string{},
		josev2.WithCustomClaims(customClaims),
		josev2.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the josev2 validator: %v", err)
	}

	// Set up the middleware.
	middleware := jwtmiddleware.New(validator.ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", middleware.CheckJWT(handler))

	// Try it out with:
	//
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb3NldjItZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.1v7S4aF7lVM92bRZ8tVTrKGZ6FwkX-7ybZQA5A7mq8E
	//
	// which is signed with 'secret' and has the data:
	// {
	//   "iss": "josev2-example",
	//   "sub": "1234567890",
	//   "name": "John Doe",
	//   "iat": 1516239022,
	//   "username": "user123"
	// }
	//
	// You can also try out the custom validation with:
	//
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb3NldjItZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyIsInNob3VsZFJlamVjdCI6dHJ1ZX0.vy-dBpmjnULan2TIHSnGCv-e7Az_mF9yNUe07qf3t8w
	//
	// which is signed with 'secret' and has the data:
	// {
	//	 "iss": "josev2-example",
	//	 "sub": "1234567890",
	//   "name": "John Doe",
	//	 "iat": 1516239022,
	//	 "username": "user123",
	//	 "shouldReject": true
	// }
}
