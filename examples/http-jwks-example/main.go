package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/go-jose/go-jose/v4"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
	if !ok {
		http.Error(w, "failed to get validated claims", http.StatusInternalServerError)
		return
	}

	if len(claims.RegisteredClaims.Subject) == 0 {
		http.Error(w, "subject in JWT claims was empty", http.StatusBadRequest)
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

	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)

	// Set up the validator.
	jwtValidator, err := validator.New(
		provider.KeyFunc,
		jose.RS256,
		issuerURL.String(),
		audience,
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	return jwtmiddleware.New(jwtValidator.ValidateToken).CheckJWT(handler)
}

func main() {
	mainHandler := setupHandler("https://<your tenant domain>/", []string{"<your api identifier>"})
	http.ListenAndServe("0.0.0.0:3000", mainHandler)
}
