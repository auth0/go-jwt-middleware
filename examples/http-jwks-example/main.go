package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/auth0/go-jwt-middleware/validate/josev2"

	"github.com/auth0/go-jwt-middleware"
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

func main() {
	issuerURL, err := url.Parse("https://<your tenant domain>")
	if err != nil {
		log.Fatalf("failed to parse the issuer url: %v", err)
	}

	provider := josev2.NewCachingJWKSProvider(issuerURL, 5*time.Minute)

	// Set up the josev2 validator.
	validator, err := josev2.New(
		provider.KeyFunc,
		jose.RS256,
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
