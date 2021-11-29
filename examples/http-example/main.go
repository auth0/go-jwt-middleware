package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/auth0/go-jwt-middleware/validate/josev2"

	"github.com/auth0/go-jwt-middleware"
)

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

	// Set up the josev2 validator.
	validator, err := josev2.New(
		keyFunc,
		jose.HS256,
		"josev2-example",
		jwt.Audience{},
	)
	if err != nil {
		log.Fatalf("failed to set up the josev2 validator: %v", err)
	}

	// Set up the middleware.
	middleware := jwtmiddleware.New(validator.ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", middleware.CheckJWT(handler))
}
