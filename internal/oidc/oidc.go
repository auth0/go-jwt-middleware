package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// WellKnownEndpoints holds the well known OIDC endpoints.
type WellKnownEndpoints struct {
	Issuer  string `json:"issuer"`   // The issuer identifier from the metadata
	JWKSURI string `json:"jwks_uri"` // URL to fetch JSON Web Keys
}

// DiscoveryOptions controls optional security validations on OIDC discovery metadata.
type DiscoveryOptions struct {
	// StrictJWKSURIOrigin requires the jwks_uri to share the same scheme+host as the
	// issuer URL. Enable this for providers known to serve JWKS from the same origin
	// (Auth0, Okta, Azure AD). Providers like Google/Firebase use a different host for
	// jwks_uri and would fail this check.
	StrictJWKSURIOrigin bool
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
//  3. Enforce HTTPS on jwks_uri (unless issuer itself uses HTTP for local dev)
//  4. Optionally validate jwks_uri origin matches issuer origin (StrictJWKSURIOrigin)
//  5. Return validated metadata with jwks_uri
//
// Parameters:
//   - expectedIssuer: The issuer claim from the JWT token (validated by the caller before discovery is invoked)
//   - httpClient: HTTP client for fetching metadata
//   - opts: Optional discovery validation options
//
// Returns error if:
//   - OIDC discovery fails
//   - Metadata's issuer doesn't match expectedIssuer
//   - Required fields (issuer, jwks_uri) are missing
//   - jwks_uri uses HTTP when issuer uses HTTPS
//   - jwks_uri origin doesn't match issuer (when StrictJWKSURIOrigin is enabled)
func GetWellKnownEndpointsFromIssuerURL(
	ctx context.Context,
	httpClient *http.Client,
	issuerURL url.URL,
	expectedIssuer string,
	opts ...DiscoveryOptions,
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

	// Limit response body to 1 MB to prevent memory exhaustion from oversized responses.
	const maxResponseBytes = 1 << 20
	limitedBody := io.LimitReader(response.Body, maxResponseBytes)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(limitedBody)
		return nil, fmt.Errorf("received HTTP %d from %s: %s",
			response.StatusCode, issuerURL.String(), string(body))
	}

	var wkEndpoints WellKnownEndpoints
	if err := json.NewDecoder(limitedBody).Decode(&wkEndpoints); err != nil {
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

	// Parse jwks_uri for security validations.
	jwksURL, err := url.Parse(wkEndpoints.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("invalid jwks_uri %q in OIDC metadata: %w", wkEndpoints.JWKSURI, err)
	}

	expectedURL, err := url.Parse(expectedIssuer)
	if err != nil {
		return nil, fmt.Errorf("invalid expected issuer URL %q: %w", expectedIssuer, err)
	}

	// Enforce HTTPS on jwks_uri when the issuer uses HTTPS.
	// If a compromised discovery endpoint injects an http:// jwks_uri, the JWKS fetch
	// would happen without TLS, allowing MITM to inject attacker-controlled keys.
	// HTTP is allowed only when the issuer itself uses HTTP (local dev/testing).
	if expectedURL.Scheme == "https" && jwksURL.Scheme != "https" {
		return nil, fmt.Errorf(
			"jwks_uri %q must use HTTPS when issuer %q uses HTTPS",
			wkEndpoints.JWKSURI,
			expectedIssuer,
		)
	}

	// Merge discovery options (variadic to keep the API backward-compatible).
	var options DiscoveryOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	// Optional strict origin validation: jwks_uri must share scheme+host with issuer.
	// Enable for providers known to serve JWKS from the same origin (Auth0, Okta, Azure AD).
	if options.StrictJWKSURIOrigin {
		if !sameOrigin(jwksURL, expectedURL) {
			return nil, fmt.Errorf(
				"jwks_uri origin mismatch: jwks_uri %q does not share the same origin as issuer %q",
				wkEndpoints.JWKSURI,
				expectedIssuer,
			)
		}
	}

	return &wkEndpoints, nil
}

// sameOrigin compares two URLs for same-origin equality following RFC 3986:
//   - Schemes are compared case-insensitively (Section 3.1)
//   - Hosts are compared case-insensitively (Section 3.2.2)
//   - Default ports are normalized (e.g., :443 for HTTPS, :80 for HTTP)
func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	return strings.EqualFold(normalizeHost(a), normalizeHost(b))
}

// normalizeHost returns the hostname:port with default ports stripped,
// so that "example.com" and "example.com:443" compare equal for HTTPS.
func normalizeHost(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		return host
	}
	// Strip default ports per scheme.
	if (strings.EqualFold(u.Scheme, "https") && port == "443") ||
		(strings.EqualFold(u.Scheme, "http") && port == "80") {
		return host
	}
	return host + ":" + port
}
