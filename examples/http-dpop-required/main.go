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
	signingKey = []byte("secret-key-for-dpop-required-example")
	issuer     = "dpop-required-example"
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

// handler demonstrates DPoP Required mode - ONLY accepts DPoP tokens
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

	// In DPoP Required mode, we ALWAYS have DPoP context
	dpopCtx := jwtmiddleware.GetDPoPContext(r.Context())

	response := map[string]any{
		"message":    "DPoP Required Mode - Only DPoP tokens accepted",
		"subject":    claims.RegisteredClaims.Subject,
		"scope":      customClaims.Scope,
		"issuer":     claims.RegisteredClaims.Issuer,
		"audience":   claims.RegisteredClaims.Audience,
		"token_type": "DPoP",
		"dpop_info": map[string]any{
			"public_key_thumbprint": dpopCtx.PublicKeyThumbprint,
			"issued_at":             dpopCtx.IssuedAt.Format(time.RFC3339),
		},
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

	// DPoP Required Mode:
	// - ONLY accepts DPoP tokens (with proof validation)
	// - REJECTS Bearer tokens (returns 400 Bad Request)
	// - Maximum security - all tokens are sender-constrained
	// - Use when all clients have migrated to DPoP
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
		jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPRequired),
		// Optional: Customize DPoP proof validation timeouts
		jwtmiddleware.WithDPoPProofOffset(60*time.Second), // Proof valid for 60 seconds
		jwtmiddleware.WithDPoPIATLeeway(30*time.Second),   // Allow 30s clock skew
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	log.Println("🔒 DPoP Required Mode Example")
	log.Println("📋 This server ONLY accepts DPoP tokens")
	log.Println("⛔ Bearer tokens will be rejected")
	log.Println("")
	log.Println("Try these requests:")
	log.Println("")
	log.Println("✅ Valid DPoP Token:")
	log.Println("   curl -H 'Authorization: DPoP <dpop-token>' \\")
	log.Println("        -H 'DPoP: <dpop-proof>' \\")
	log.Println("        http://localhost:3001/")
	log.Println("")
	log.Println("❌ Bearer Token (will be rejected):")
	log.Println("   curl -H 'Authorization: Bearer <token>' http://localhost:3001/")
	log.Println("   Response: 400 Bad Request - Bearer tokens are not allowed")
	log.Println("")
	log.Println("Server listening on :3001")

	http.ListenAndServe(":3001", middleware.CheckJWT(handler))
}
