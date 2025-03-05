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

// WithSynchronousRefresh sets whether the CachingProvider blocks on refresh.
// If set to true, it will block and wait for the refresh to complete.
// If set to false (default), it will return the cached JWKS and trigger a background refresh.
func WithSynchronousRefresh(blocking bool) CachingProviderOption {
	return func(cp *CachingProvider) {
		cp.synchronousRefresh = blocking
	}
}
