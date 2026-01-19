package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

var (
	signingKey = []byte("secret")
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
	// Modern type-safe claims retrieval using generics
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	if err != nil {
		http.Error(w, "failed to get validated claims", http.StatusInternalServerError)
		return
	}

	customClaims, ok := claims.CustomClaims.(*CustomClaimsExample)
	if !ok {
		http.Error(w, "could not cast custom claims to specific type", http.StatusInternalServerError)
		return
	}

	if len(customClaims.Username) == 0 {
		http.Error(w, "username in JWT claims was empty", http.StatusBadRequest)
		return
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
	keyFunc := func(ctx context.Context) (any, error) {
		// Our token must be signed using this data.
		return signingKey, nil
	}

	// Set up the validator.
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience),
		// WithCustomClaims now uses generics - no need to return interface type
		validator.WithCustomClaims(func() *CustomClaimsExample {
			return &CustomClaimsExample{}
		}),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Set up the middleware using pure options pattern
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
		// Optional: Add a logger for debugging JWT validation flow
		// jwtmiddleware.WithLogger(slog.Default()),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	return middleware.CheckJWT(handler)
}

func main() {
	mainHandler := setupHandler()
	http.ListenAndServe("0.0.0.0:3000", mainHandler)

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
