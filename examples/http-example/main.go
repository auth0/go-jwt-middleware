package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/auth0/go-jwt-middleware/validator"

	"github.com/auth0/go-jwt-middleware"
)

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

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

func main() {
	keyFunc := func(ctx context.Context) (interface{}, error) {
		// Our token must be signed using this data.
		return []byte("secret"), nil
	}

	// We want this struct to be filled in with
	// our custom claims from the token.
	customClaims := &CustomClaimsExample{}

	// Set up the validator.
	jwtValidator, err := validator.New(
		keyFunc,
		"HS256",
		"go-jwt-middleware-example",
		[]string{"audience-example"},
		validator.WithCustomClaims(customClaims),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Set up the middleware.
	middleware := jwtmiddleware.New(jwtValidator.ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", middleware.CheckJWT(handler))

	// Try it out with:
	//
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.XFhrzWzntyINkgoRt2mb8dES84dJcuOoORdzKfwUX70
	//
	// which is signed with 'secret' and has the data:
	// {
	//   "iss": "go-jwt-middleware-example",
	//   "aud": "audience-example",
	//   "sub": "1234567890",
	//   "name": "John Doe",
	//   "iat": 1516239022,
	//   "username": "user123"
	// }
	//
	// You can also try out the custom validation with:
	//
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyIsInNob3VsZFJlamVjdCI6dHJ1ZX0.Jf13PY_Oyu2x3Gx1JQ0jXRiWaCOb5T2RbKOrTPBNHJA
	//
	// which is signed with 'secret' and has the data:
	// {
	//   "iss": "go-jwt-middleware-example",
	//   "aud": "audience-example",
	//   "sub": "1234567890",
	//   "name": "John Doe",
	//   "iat": 1516239022,
	//   "username": "user123",
	//   "shouldReject": true
	// }
}
