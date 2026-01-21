package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
)

// WellKnownEndpoints holds the well known OIDC endpoints.
type WellKnownEndpoints struct {
	Issuer  string `json:"issuer"`   // The issuer identifier from the metadata
	JWKSURI string `json:"jwks_uri"` // URL to fetch JSON Web Keys
}

// GetWellKnownEndpointsFromIssuerURL gets the well known endpoints for the passed in issuer url
// and validates that the metadata's issuer field exactly matches the expected issuer.
//
// This implements MCD (Multiple Custom Domains) requirement #4:
// Double-validation of issuer to prevent token substitution attacks.
//
// Validation flow:
//  1. Fetch OIDC discovery metadata from https://<domain>/.well-known/openid-configuration
//  2. Validate metadata's issuer field matches expectedIssuer (exact match)
//  3. Return validated metadata with jwks_uri
//
// Parameters:
//   - expectedIssuer: The issuer claim from the JWT token (already validated in step 3)
//   - httpClient: HTTP client for fetching metadata
//
// Returns error if:
//   - OIDC discovery fails
//   - Metadata's issuer doesn't match expectedIssuer
//   - Required fields (issuer, jwks_uri) are missing
func GetWellKnownEndpointsFromIssuerURL(
	ctx context.Context,
	httpClient *http.Client,
	issuerURL url.URL,
	expectedIssuer string,
) (*WellKnownEndpoints, error) {
	issuerURL.Path = path.Join(issuerURL.Path, ".well-known/openid-configuration")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, issuerURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get well-known endpoints: %w", err)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("could not fetch well-known endpoints from %s: %w", issuerURL.String(), err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("received HTTP %d from %s: %s",
			response.StatusCode, issuerURL.String(), string(body))
	}

	var wkEndpoints WellKnownEndpoints
	if err := json.NewDecoder(response.Body).Decode(&wkEndpoints); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response from %s: %w", issuerURL.String(), err)
	}

	// Validate that the issuer field in metadata is present
	if wkEndpoints.Issuer == "" {
		return nil, fmt.Errorf("OIDC discovery metadata missing required 'issuer' field")
	}

	// Validate that JWKS URI is present
	if wkEndpoints.JWKSURI == "" {
		return nil, fmt.Errorf("OIDC discovery metadata missing required 'jwks_uri' field")
	}

	// Double-validation: Ensure metadata's issuer matches the token's issuer
	// This prevents attacks where an attacker substitutes a token from a different issuer
	if wkEndpoints.Issuer != expectedIssuer {
		return nil, fmt.Errorf(
			"issuer mismatch: metadata issuer %q does not match token issuer %q",
			wkEndpoints.Issuer,
			expectedIssuer,
		)
	}

	return &wkEndpoints, nil
}