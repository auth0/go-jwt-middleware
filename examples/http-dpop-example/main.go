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
	signingKey = []byte("secret")
	issuer     = "go-jwt-middleware-dpop-example"
	audience   = []string{"audience-example"}
)

// CustomClaimsExample contains custom data we want from the token.
type CustomClaimsExample struct {
	Name     string `json:"name"`
	Username string `json:"username"`
}

// Validate implements validator.CustomClaims.
func (c *CustomClaimsExample) Validate(ctx context.Context) error {
	return nil
}

// handler demonstrates accessing both JWT claims and DPoP context
var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get JWT claims
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

	// Build response with both JWT and DPoP information
	response := map[string]any{
		"subject":  claims.RegisteredClaims.Subject,
		"username": customClaims.Username,
		"name":     customClaims.Name,
		"issuer":   claims.RegisteredClaims.Issuer,
	}

	// Check if this is a DPoP request and add DPoP context information
	if jwtmiddleware.HasDPoPContext(r.Context()) {
		dpopCtx := jwtmiddleware.GetDPoPContext(r.Context())
		response["dpop_enabled"] = true
		response["token_type"] = dpopCtx.TokenType
		response["public_key_thumbprint"] = dpopCtx.PublicKeyThumbprint
		response["dpop_issued_at"] = dpopCtx.IssuedAt.Format(time.RFC3339)
	} else {
		response["dpop_enabled"] = false
		response["token_type"] = "Bearer"
	}

	payload, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

func setupHandler() http.Handler {
	keyFunc := func(ctx context.Context) (any, error) {
		return signingKey, nil
	}

	// Set up the validator.
	// The same validator instance will be used for both JWT validation and DPoP proof validation.
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience),
		validator.WithCustomClaims(func() *CustomClaimsExample {
			return &CustomClaimsExample{}
		}),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Set up the middleware with DPoP support.
	// WithValidator automatically detects that jwtValidator supports DPoP
	// (has ValidateDPoPProof method) and enables DPoP validation.
	// By default, DPoP mode is "allowed" which means both Bearer and DPoP tokens are accepted.
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator), // Automatically enables JWT + DPoP!

		// Optional: Configure DPoP mode
		// - jwtmiddleware.DPoPAllowed (default): Accept both Bearer and DPoP tokens
		// - jwtmiddleware.DPoPRequired: Only accept DPoP tokens (reject Bearer tokens)
		// - jwtmiddleware.DPoPDisabled: Only accept Bearer tokens (reject DPoP tokens)
		// jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPRequired),

		// Optional: Configure time constraints
		jwtmiddleware.WithDPoPProofOffset(5*time.Minute), // DPoP proof must be issued within last 5 minutes (default: 300s)
		jwtmiddleware.WithDPoPIATLeeway(5*time.Second),   // Allow 5 seconds clock skew for iat validation (default: 5s)
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	return middleware.CheckJWT(handler)
}

func main() {
	mainHandler := setupHandler()

	log.Println("===========================================")
	log.Println("DPoP Example Server")
	log.Println("===========================================")
	log.Println("Server listening on http://0.0.0.0:3000")
	log.Println()
	log.Println("This example demonstrates DPoP (Demonstrating Proof-of-Possession) support")
	log.Println("per RFC 9449. The middleware is configured to accept both Bearer and DPoP tokens.")
	log.Println()
	log.Println("DPoP provides stronger security than Bearer tokens by binding the access token")
	log.Println("to a cryptographic key pair. The client must prove possession of the private key")
	log.Println("for each request.")
	log.Println()
	log.Println("===========================================")
	log.Println("Example 1: Bearer Token (Standard JWT)")
	log.Println("===========================================")
	log.Println()
	log.Println("A standard Bearer token without DPoP binding:")
	log.Println()
	log.Println("  curl -H 'Authorization: Bearer <token>' http://localhost:3000/")
	log.Println()
	log.Println("Example Bearer Token:")
	log.Println("  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1kcG9wLWV4YW1wbGUiLCJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkpvaG4gRG9lIiwidXNlcm5hbWUiOiJqb2huZG9lIiwiaWF0IjoxNzM3NzEwNDAwLCJleHAiOjIwNTMwNzA0MDB9.XrR9VVlBfZ3GJ_f1vI-YpT2ILQX5qkF9Fb6HHNJZVgQ")
	log.Println()
	log.Println("Token payload:")
	log.Println("  {")
	log.Println("    \"iss\": \"go-jwt-middleware-dpop-example\",")
	log.Println("    \"aud\": [\"audience-example\"],")
	log.Println("    \"sub\": \"user123\",")
	log.Println("    \"name\": \"John Doe\",")
	log.Println("    \"username\": \"johndoe\",")
	log.Println("    \"iat\": 1737710400,")
	log.Println("    \"exp\": 2053070400")
	log.Println("  }")
	log.Println()
	log.Println("===========================================")
	log.Println("Example 2: DPoP Token (With Proof)")
	log.Println("===========================================")
	log.Println()
	log.Println("A DPoP token requires TWO headers:")
	log.Println("  1. Authorization header with 'DPoP' scheme and access token")
	log.Println("  2. DPoP header with the DPoP proof JWT")
	log.Println()
	log.Println("  curl -H 'Authorization: DPoP <access_token>' \\")
	log.Println("       -H 'DPoP: <dpop_proof>' \\")
	log.Println("       http://localhost:3000/")
	log.Println()
	log.Println("The access token must contain a 'cnf' (confirmation) claim with the 'jkt'")
	log.Println("(JWK thumbprint) that binds it to the DPoP proof's public key.")
	log.Println()
	log.Println("Access Token payload example:")
	log.Println("  {")
	log.Println("    \"iss\": \"go-jwt-middleware-dpop-example\",")
	log.Println("    \"aud\": [\"audience-example\"],")
	log.Println("    \"sub\": \"user456\",")
	log.Println("    \"name\": \"Jane Smith\",")
	log.Println("    \"username\": \"janesmith\",")
	log.Println("    \"cnf\": {")
	log.Println("      \"jkt\": \"<base64url-encoded-thumbprint>\"")
	log.Println("    },")
	log.Println("    \"iat\": 1737710400,")
	log.Println("    \"exp\": 2053070400")
	log.Println("  }")
	log.Println()
	log.Println("DPoP Proof JWT header:")
	log.Println("  {")
	log.Println("    \"typ\": \"dpop+jwt\",")
	log.Println("    \"alg\": \"ES256\",")
	log.Println("    \"jwk\": {")
	log.Println("      \"kty\": \"EC\",")
	log.Println("      \"crv\": \"P-256\",")
	log.Println("      \"x\": \"...\",")
	log.Println("      \"y\": \"...\"")
	log.Println("    }")
	log.Println("  }")
	log.Println()
	log.Println("DPoP Proof JWT payload:")
	log.Println("  {")
	log.Println("    \"jti\": \"unique-proof-id\",")
	log.Println("    \"htm\": \"GET\",")
	log.Println("    \"htu\": \"http://localhost:3000/\",")
	log.Println("    \"iat\": 1737710400")
	log.Println("  }")
	log.Println()
	log.Println("===========================================")
	log.Println("Middleware Configuration Options")
	log.Println("===========================================")
	log.Println()
	log.Println("DPoP Mode:")
	log.Println("  - jwtmiddleware.DPoPAllowed (default):  Accept both Bearer and DPoP tokens")
	log.Println("  - jwtmiddleware.DPoPRequired:            Only accept DPoP tokens")
	log.Println("  - jwtmiddleware.DPoPDisabled:            Only accept Bearer tokens")
	log.Println()
	log.Println("Time Constraints:")
	log.Println("  - WithDPoPProofOffset(duration): Maximum age of DPoP proof (default: 5m)")
	log.Println("  - WithDPoPIATLeeway(duration):   Clock skew tolerance (default: 5s)")
	log.Println()
	log.Println("===========================================")
	log.Println("Accessing DPoP Context in Handlers")
	log.Println("===========================================")
	log.Println()
	log.Println("  // Check if DPoP context exists")
	log.Println("  if jwtmiddleware.HasDPoPContext(r.Context()) {")
	log.Println("    // Get DPoP context")
	log.Println("    dpopCtx := jwtmiddleware.GetDPoPContext(r.Context())")
	log.Println("    ")
	log.Println("    // Access DPoP information")
	log.Println("    fmt.Println(dpopCtx.TokenType)              // \"DPoP\"")
	log.Println("    fmt.Println(dpopCtx.PublicKeyThumbprint)    // JKT")
	log.Println("    fmt.Println(dpopCtx.IssuedAt)               // Proof iat")
	log.Println("    fmt.Println(dpopCtx.PublicKey)              // Public key")
	log.Println("  }")
	log.Println()
	log.Println("===========================================")

	if err := http.ListenAndServe("0.0.0.0:3000", mainHandler); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
