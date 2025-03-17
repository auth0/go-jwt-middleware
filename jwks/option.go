package jwks

import (
	"net/http"
	"net/url"
)

// ProviderOption is how options for the Provider are set up.
type ProviderOption func(*Provider)

// CachingProviderOption is how options for the CachingProvider are set up.
type CachingProviderOption func(*CachingProvider)

// WithCustomJWKSURI will set a custom JWKS URI on the *Provider and
// call this directly inside the keyFunc in order to fetch the JWKS,
// skipping the oidc.GetWellKnownEndpointsFromIssuerURL call.
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(p *Provider) {
		p.CustomJWKSURI = jwksURI
	}
}

// WithCustomClient will set a custom *http.Client on the *Provider
func WithCustomClient(c *http.Client) ProviderOption {
	return func(p *Provider) {
		p.Client = c
	}
}
