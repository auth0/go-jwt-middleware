package main

import (
	"encoding/json"
	"log"
	"net/http"
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

	// Show which issuer validated the token
	response := map[string]any{
		"issuer":  claims.RegisteredClaims.Issuer,
		"subject": claims.RegisteredClaims.Subject,
		"claims":  claims,
	}

	payload, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

func setupHandler(issuers []string, audience []string) http.Handler {
	// Use MultiIssuerProvider to handle multiple issuers
	provider, err := jwks.NewMultiIssuerProvider(
		jwks.WithMultiIssuerCacheTTL(5*time.Minute),
	)
	if err != nil {
		log.Fatalf("failed to create multi-issuer jwks provider: %v", err)
	}

	// Set up the validator with multiple issuers
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuers(issuers), // Multiple issuers
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
	// Configure multiple issuers - tokens from any of these issuers will be accepted
	issuers := []string{
		"https://tenant1.auth0.com/",
		"https://tenant2.auth0.com/",
		"https://tenant3.auth0.com/",
		// Add more issuers as needed
	}

	mainHandler := setupHandler(issuers, []string{"<your api identifier>"})

	log.Println("Server listening on http://localhost:3000")
	log.Println("Accepting tokens from multiple issuers:")
	for _, issuer := range issuers {
		log.Printf("  - %s", issuer)
	}

	if err := http.ListenAndServe("0.0.0.0:3000", mainHandler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
