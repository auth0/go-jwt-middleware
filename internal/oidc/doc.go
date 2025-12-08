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

# Usage

	import (
	    "github.com/auth0/go-jwt-middleware/v3/internal/oidc"
	)

	issuerURL, _ := url.Parse("https://auth.example.com/")
	client := &http.Client{Timeout: 10 * time.Second}

	endpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, client, *issuerURL)
	if err != nil {
	    // Handle error
	}

	// Access JWKS URI
	jwksURI := endpoints.JWKSURI

# Endpoints Struct

The WellKnownEndpoints struct contains commonly used OIDC endpoints:

	type WellKnownEndpoints struct {
	    Issuer                string // Issuer identifier
	    JWKSURI               string // JSON Web Key Set URI
	    AuthorizationEndpoint string // OAuth 2.0 authorization endpoint
	    TokenEndpoint         string // OAuth 2.0 token endpoint
	}

# Error Handling

	endpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, client, issuerURL)
	if err != nil {
	    // Possible errors:
	    // - Network failure
	    // - HTTP error status (e.g., 404, 500)
	    // - Invalid JSON response
	    // - Missing required fields
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
