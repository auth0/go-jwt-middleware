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
	issuer     = "go-jwt-middleware-dpop-proxy-example"
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
		"subject":       claims.RegisteredClaims.Subject,
		"username":      customClaims.Username,
		"name":          customClaims.Name,
		"issuer":        claims.RegisteredClaims.Issuer,
		"request_url":   r.URL.String(),
		"request_host":  r.Host,
		"request_proto": r.Proto,
	}

	// Add proxy headers information if present
	proxyHeaders := make(map[string]string)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		proxyHeaders["X-Forwarded-Proto"] = proto
	}
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		proxyHeaders["X-Forwarded-Host"] = host
	}
	if prefix := r.Header.Get("X-Forwarded-Prefix"); prefix != "" {
		proxyHeaders["X-Forwarded-Prefix"] = prefix
	}
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		proxyHeaders["Forwarded"] = forwarded
	}
	if len(proxyHeaders) > 0 {
		response["proxy_headers"] = proxyHeaders
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

	// Set up the middleware with DPoP support and TRUSTED PROXY CONFIGURATION.
	//
	// SECURITY WARNING: Only enable trusted proxies when your application is behind
	// a reverse proxy that STRIPS client-provided forwarded headers. DO NOT use this
	// for direct internet-facing deployments as it allows header injection attacks.
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),

		// OPTION 1: Standard Proxy Configuration (Nginx, Apache, HAProxy)
		// Trusts X-Forwarded-Proto and X-Forwarded-Host headers
		jwtmiddleware.WithStandardProxy(),

		// OPTION 2: API Gateway Configuration (AWS API Gateway, Kong, Traefik)
		// Trusts X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-Prefix
		// Uncomment to use instead of WithStandardProxy():
		// jwtmiddleware.WithAPIGatewayProxy(),

		// OPTION 3: RFC 7239 Forwarded Header (most secure, structured format)
		// Uncomment to use instead of WithStandardProxy():
		// jwtmiddleware.WithRFC7239Proxy(),

		// OPTION 4: Custom Configuration (granular control)
		// Uncomment to use instead of WithStandardProxy():
		// jwtmiddleware.WithTrustedProxies(&jwtmiddleware.TrustedProxyConfig{
		//     TrustXForwardedProto:  true,  // Trust scheme (https/http)
		//     TrustXForwardedHost:   true,  // Trust original hostname
		//     TrustXForwardedPrefix: false, // Don't trust path prefix
		//     TrustForwarded:        false, // Don't trust RFC 7239
		// }),

		// Optional DPoP configuration
		jwtmiddleware.WithDPoPProofOffset(5*time.Minute),
		jwtmiddleware.WithDPoPIATLeeway(5*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	return middleware.CheckJWT(handler)
}

func main() {
	mainHandler := setupHandler()

	log.Println("===========================================")
	log.Println("DPoP with Trusted Proxy Example")
	log.Println("===========================================")
	log.Println("Server listening on http://0.0.0.0:3000")
	log.Println()
	log.Println("This example demonstrates DPoP with trusted proxy configuration")
	log.Println("for reverse proxy deployments (Nginx, Apache, HAProxy, API Gateways).")
	log.Println()
	log.Println("SECURITY WARNING: Only enable trusted proxies when behind a reverse")
	log.Println("proxy that STRIPS client-provided forwarded headers!")
	log.Println()
	log.Println("===========================================")
	log.Println("Example Bearer Token (valid until 2035):")
	log.Println("===========================================")
	log.Println("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4")
	log.Println()
	log.Println("===========================================")
	log.Println("Test with X-Forwarded headers:")
	log.Println("===========================================")
	log.Println("curl -H 'Authorization: Bearer <token>' \\")
	log.Println("     -H 'X-Forwarded-Proto: https' \\")
	log.Println("     -H 'X-Forwarded-Host: api.example.com' \\")
	log.Println("     http://localhost:3000/users")
	log.Println()
	log.Println("===========================================")
	log.Println("Test with RFC 7239 Forwarded header:")
	log.Println("===========================================")
	log.Println("curl -H 'Authorization: Bearer <token>' \\")
	log.Println("     -H 'Forwarded: proto=https;host=api.example.com' \\")
	log.Println("     http://localhost:3000/users")
	log.Println()
	log.Println("===========================================")
	log.Println("Proxy Configuration Options:")
	log.Println("===========================================")
	log.Println("1. WithStandardProxy() - Nginx, Apache, HAProxy")
	log.Println("2. WithAPIGatewayProxy() - AWS API Gateway, Kong, Traefik")
	log.Println("3. WithRFC7239Proxy() - RFC 7239 Forwarded header")
	log.Println("4. WithTrustedProxies() - Custom configuration")
	log.Println()
	log.Println("See README.md for detailed documentation and security best practices")
	log.Println("===========================================")

	if err := http.ListenAndServe("0.0.0.0:3000", mainHandler); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
