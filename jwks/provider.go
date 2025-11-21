package jwks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/auth0/go-jwt-middleware/v3/internal/oidc"
)

// Provider handles getting JWKS from the specified IssuerURL and exposes
// KeyFunc which adheres to the keyFunc signature that the Validator requires.
// Most likely you will want to use the CachingProvider as it handles
// getting and caching JWKS which can help reduce request time and potential
// rate limiting from your provider.
type Provider struct {
	IssuerURL     *url.URL // Required.
	CustomJWKSURI *url.URL // Optional.
	Client        *http.Client
}

// ProviderOption is how options for the Provider are set up.
type ProviderOption func(*Provider)

// NewProvider builds and returns a new *Provider.
func NewProvider(issuerURL *url.URL, opts ...ProviderOption) *Provider {
	p := &Provider{
		IssuerURL: issuerURL,
		Client:    &http.Client{},
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

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

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be jwk.Set.
func (p *Provider) KeyFunc(ctx context.Context) (interface{}, error) {
	jwksURI := p.CustomJWKSURI
	if jwksURI == nil {
		wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, p.Client, *p.IssuerURL)
		if err != nil {
			return nil, err
		}

		jwksURI, err = url.Parse(wkEndpoints.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("could not parse JWKS URI from well known endpoints: %w", err)
		}
	}

	// Fetch JWKS using jwx
	set, err := jwk.Fetch(ctx, jwksURI.String(), jwk.WithHTTPClient(p.Client))
	if err != nil {
		return nil, fmt.Errorf("could not fetch JWKS: %w", err)
	}

	return set, nil
}

// CachingProvider handles getting JWKS from the specified IssuerURL
// and caching them using jwx's built-in cache. It exposes KeyFunc which
// adheres to the keyFunc signature that the Validator requires.
// The cache automatically handles background refresh and concurrency.
type CachingProvider struct {
	cache       *jwk.Cache
	jwksURI     string
	issuerURL   *url.URL
	httpClient  *http.Client
	cacheTTL    time.Duration
}

type CachingProviderOption func(*CachingProvider)

// NewCachingProvider builds and returns a new CachingProvider.
// If cacheTTL is zero then a default value of 1 minute will be used.
// The cache automatically handles background refresh.
func NewCachingProvider(issuerURL *url.URL, cacheTTL time.Duration, opts ...interface{}) *CachingProvider {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Minute
	}

	cp := &CachingProvider{
		issuerURL:  issuerURL,
		httpClient: &http.Client{},
		cacheTTL:   cacheTTL,
	}

	// Parse options
	var customJWKSURI *url.URL
	for _, opt := range opts {
		switch o := opt.(type) {
		case ProviderOption:
			// Handle ProviderOptions by applying to temp provider
			tempProvider := &Provider{}
			o(tempProvider)
			if tempProvider.CustomJWKSURI != nil {
				customJWKSURI = tempProvider.CustomJWKSURI
			}
			if tempProvider.Client != nil {
				cp.httpClient = tempProvider.Client
			}
		case CachingProviderOption:
			o(cp)
		default:
			panic(fmt.Sprintf("invalid option type: %T", o))
		}
	}

	// Determine JWKS URI
	if customJWKSURI != nil {
		cp.jwksURI = customJWKSURI.String()
	} else {
		// We'll discover it on first use via well-known endpoint
		cp.jwksURI = ""
	}

	// Initialize jwx cache with background context and HTTP client
	// Cache will be long-lived for the lifetime of the provider
	httprcClient := httprc.NewClient(httprc.WithHTTPClient(cp.httpClient))
	cache, err := jwk.NewCache(context.Background(), httprcClient)
	if err != nil {
		panic(fmt.Sprintf("failed to create JWKS cache: %v", err))
	}
	cp.cache = cache

	return cp
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be jwk.Set.
func (c *CachingProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	// Discover JWKS URI if not already set
	if c.jwksURI == "" {
		wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, c.httpClient, *c.issuerURL)
		if err != nil {
			return nil, err
		}
		c.jwksURI = wkEndpoints.JWKSURI
	}

	// Register the JWKS URI with automatic background refresh
	// Register is idempotent - safe to call multiple times
	err := c.cache.Register(ctx, c.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("could not register JWKS URI: %w", err)
	}

	// Fetch from cache (will fetch from network if not cached or expired)
	cachedSet, err := c.cache.Refresh(ctx, c.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("could not refresh JWKS: %w", err)
	}

	return cachedSet, nil
}
