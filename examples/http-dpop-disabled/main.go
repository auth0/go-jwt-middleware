package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

var (
	signingKey = []byte("secret-key-for-dpop-disabled-example")
	issuer     = "dpop-disabled-example"
	audience   = []string{"https://api.example.com"}
)

// CustomClaims contains custom data we want from the token.
type CustomClaims struct {
	Scope string `json:"scope"`
}

// Validate implements validator.CustomClaims.
func (c *CustomClaims) Validate(ctx context.Context) error {
	return nil
}

// handler demonstrates DPoP Disabled mode - ONLY accepts Bearer tokens
var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	if err != nil {
		http.Error(w, "failed to get validated claims", http.StatusInternalServerError)
		return
	}

	customClaims, ok := claims.CustomClaims.(*CustomClaims)
	if !ok {
		http.Error(w, "could not cast custom claims", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"message":    "DPoP Disabled Mode - Only Bearer tokens accepted",
		"subject":    claims.RegisteredClaims.Subject,
		"scope":      customClaims.Scope,
		"issuer":     claims.RegisteredClaims.Issuer,
		"audience":   claims.RegisteredClaims.Audience,
		"token_type": "Bearer",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
})

func main() {
	keyFunc := func(ctx context.Context) (any, error) {
		return signingKey, nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience),
		validator.WithCustomClaims(func() *CustomClaims {
			return &CustomClaims{}
		}),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// DPoP Disabled Mode:
	// - ONLY accepts Bearer tokens (traditional OAuth 2.0)
	// - DPoP headers are ignored
	// - Use when you want to explicitly opt-out of DPoP support
	// - Compatible with legacy systems that don't support DPoP
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
		jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPDisabled),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	log.Println("📦 DPoP Disabled Mode Example")
	log.Println("📋 This server ONLY accepts Bearer tokens")
	log.Println("⚠️  DPoP headers are ignored")
	log.Println("")
	log.Println("Try these requests:")
	log.Println("")
	log.Println("✅ Bearer Token (traditional):")
	log.Println("   curl -H 'Authorization: Bearer <token>' http://localhost:3002/")
	log.Println("")
	log.Println("⚠️  DPoP Token (headers ignored, treated as invalid):")
	log.Println("   curl -H 'Authorization: DPoP <dpop-token>' \\")
	log.Println("        -H 'DPoP: <dpop-proof>' \\")
	log.Println("        http://localhost:3002/")
	log.Println("   Response: 400 Bad Request - Invalid scheme")
	log.Println("")
	log.Println("Server listening on :3002")

	http.ListenAndServe(":3002", middleware.CheckJWT(handler))
}
