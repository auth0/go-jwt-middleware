package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

var (
	signingKey = []byte("your-256-bit-secret-is-just-enough")
	issuer     = "go-jwt-middleware-example"
	audience   = []string{"audience-example"}
)

// CustomClaimsExample contains custom data we want from the token.
type CustomClaimsExample struct {
	Name         string `json:"name"`
	Username     string `json:"username"`
	ShouldReject bool   `json:"shouldReject,omitempty"`
}

// Validate errors out if `ShouldReject` is true.
func (c *CustomClaimsExample) Validate(ctx context.Context) error {
	if c.ShouldReject {
		return errors.New("should reject was set to true")
	}
	return nil
}

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
	if !ok {
		http.Error(w, "failed to get validated claims", http.StatusInternalServerError)
		return
	}

	customClaims, ok := claims.CustomClaims.(*CustomClaimsExample)
	if !ok {
		http.Error(w, "could not cast custom claims to specific type", http.StatusInternalServerError)
	}

	if len(customClaims.Username) == 0 {
		http.Error(w, "username in JWT claims was empty", http.StatusBadRequest)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

func setupHandler() http.Handler {
	keyFunc := func(ctx context.Context) (interface{}, error) {
		// Our token must be signed using this data.
		return signingKey, nil
	}

	// We want this struct to be filled in with
	// our custom claims from the token.
	customClaims := func() validator.CustomClaims {
		return &CustomClaimsExample{}
	}

	// Set up the validator.
	jwtValidator, err := validator.New(
		keyFunc,
		validator.HS256,
		issuer,
		audience,
		validator.WithCustomClaims(customClaims),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	return jwtmiddleware.New(jwtValidator.ValidateToken).CheckJWT(handler)
}

func main() {
	mainHandler := setupHandler()
	http.ListenAndServe("0.0.0.0:3000", mainHandler)

	// Try it out with:
	//
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.efMBnTwQly3QNK8RxZeI8nscQVKMEtVqZUXC9MA6JsQ
	//
	// which is signed with 'your-256-bit-secret-is-just-enough' and has the data:
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
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyIsInNob3VsZFJlamVjdCI6dHJ1ZX0.oWqSLPLRzF2upnnIUls0rE8rANy_IaC0qrV-jjOm89M
	//
	// which is signed with 'your-256-bit-secret-is-just-enough' and has the data:
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
