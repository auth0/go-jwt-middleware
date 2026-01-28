/*
Package oidc provides OIDC (OpenID Connect) discovery functionality.

This internal package implements the logic to discover OIDC provider endpoints
by fetching the .well-known/openid-configuration document from the issuer.

# OIDC Discovery

OIDC providers expose a discovery document at a well-known URL:

	https://issuer.example.com/.well-known/openid-configuration

This document contains metadata about the provider, including:
  - issuer: The issuer identifier
  - jwks_uri: URL to fetch JSON Web Keys
  - authorization_endpoint: OAuth 2.0 authorization endpoint
  - token_endpoint: OAuth 2.0 token endpoint
  - And more...

# Double-Validation for MCD (Multiple Custom Domains)

This package performs double-validation for enhanced security:

1. Fetches OIDC discovery metadata from the issuer
2. Validates that the metadata's "issuer" field exactly matches the expected issuer
3. Returns validated metadata with jwks_uri

This prevents token substitution attacks where an attacker might try to use
a token from one issuer with JWKS from another issuer.

# Usage

	import (
	    "github.com/auth0/go-jwt-middleware/v3/internal/oidc"
	)

	issuerURL, _ := url.Parse("https://auth.example.com/")
	client := &http.Client{Timeout: 10 * time.Second}
	expectedIssuer := "https://auth.example.com/"

	endpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(
	    ctx, client, *issuerURL, expectedIssuer,
	)
	if err != nil {
	    // Handle error: network failure, issuer mismatch, or invalid response
	}

	// Access JWKS URI
	jwksURI := endpoints.JWKSURI

The expectedIssuer parameter must match the metadata's issuer field exactly,
providing defense-in-depth against token substitution attacks.

# Endpoints Struct

The WellKnownEndpoints struct contains commonly used OIDC endpoints:

	type WellKnownEndpoints struct {
	    Issuer                string // Issuer identifier
	    JWKSURI               string // JSON Web Key Set URI
	    AuthorizationEndpoint string // OAuth 2.0 authorization endpoint
	    TokenEndpoint         string // OAuth 2.0 token endpoint
	}

# Error Handling

	endpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, client, issuerURL, expectedIssuer)
	if err != nil {
	    // Possible errors:
	    // - Network failure
	    // - HTTP error status (e.g., 404, 500)
	    // - Invalid JSON response
	    // - Missing required fields (issuer, jwks_uri)
	    // - Issuer mismatch (metadata issuer != expectedIssuer)
	}

# HTTP Client Configuration

The function accepts a custom *http.Client, allowing you to configure:

  - Timeouts

  - Proxy settings

  - Custom transport

  - TLS configuration

    client := &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
    TLSClientConfig: &tls.Config{
    MinVersion: tls.VersionTLS12,
    },
    },
    }

# Specification

This package implements OIDC Discovery as defined in:
OpenID Connect Discovery 1.0
https://openid.net/specs/openid-connect-discovery-1_0.html
*/
package oidc
