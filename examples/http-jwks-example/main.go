package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Modern type-safe claims retrieval using generics
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	if err != nil {
		http.Error(w, "failed to get validated claims", http.StatusInternalServerError)
		return
	}

	if len(claims.RegisteredClaims.Subject) == 0 {
		http.Error(w, "subject in JWT claims was empty", http.StatusBadRequest)
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

func setupHandler(issuer string, audience []string) http.Handler {
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		log.Fatalf("failed to parse the issuer url: %v", err)
	}

	provider, err := jwks.NewCachingProvider(
		jwks.WithIssuerURL(issuerURL),
		jwks.WithCacheTTL(5*time.Minute),
	)
	if err != nil {
		log.Fatalf("failed to create jwks provider: %v", err)
	}

	// Set up the validator.
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuer(issuerURL.String()),
		validator.WithAudiences(audience),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Set up the middleware using pure options pattern
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	return middleware.CheckJWT(handler)
}

func main() {
	mainHandler := setupHandler("https://<your tenant domain>/", []string{"<your api identifier>"})
	http.ListenAndServe("0.0.0.0:3000", mainHandler)
}
