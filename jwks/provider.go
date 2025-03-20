package jwks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/internal/oidc"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Provider handles fetching JWKS (JSON Web Key Sets) from an issuer URL or a custom JWKS URI.
// It exposes the KeyFunc method to retrieve the keys for JWT validation.
// Use CachingProvider for better performance by reducing redundant network requests.
type Provider struct {
	IssuerURL     *url.URL     // The URL of the issuer to fetch JWKS from.
	CustomJWKSURI *url.URL     // Optional custom JWKS URI to override the issuer discovery.
	Client        *http.Client // HTTP client to use for requests.
	once          sync.Once    // Ensures that the JWKS URI initialization happens only once.
	jwksURI       *url.URL     // The resolved JWKS URI after initialization.
	initialized   bool         // Flag to track if initialization was successful
	mu            sync.Mutex   // Mutex to protect concurrent initialization attempts
}

// NewProvider creates a new Provider instance with optional configurations.
func NewProvider(issuerURL *url.URL, opts ...ProviderOption) *Provider {
	p := &Provider{
		IssuerURL: issuerURL,
		Client:    http.DefaultClient,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// KeyFunc retrieves the JWKS from the configured URI. It initializes the JWKS URI once and fetches the keys.
// It returns an error if the JWKS URI is not set or if the keys cannot be fetched.
// It returns a jwk.Set instance that can be used to verify JWT tokens.
func (p *Provider) KeyFunc(ctx context.Context) (interface{}, error) {
	p.mu.Lock()
	if !p.initialized {
		p.once = sync.Once{} // Reset once if previous initialization failed
		p.mu.Unlock()

		var initErr error
		p.once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.jwksURI, initErr = p.initJWKSURI(ctx)
			p.initialized = initErr == nil // Mark as initialized only if successful
		})

		if initErr != nil {
			return nil, initErr
		}
	} else {
		p.mu.Unlock()
	}

	return jwk.Fetch(ctx, p.jwksURI.String(), jwk.WithHTTPClient(p.Client))
}

// CachingProvider extends Provider by adding caching logic to reduce network calls and improve performance.
// It uses a refresh window to trigger cache updates before expiration and supports configurable TTL for keys.
// Use NewCachingProvider to create a CachingProvider instance with cache TTL and optional configurations.
type CachingProvider struct {
	Provider
	CacheTTL           time.Duration // Time-to-live for cache entries.
	cache              *jwk.Cache    // The JWKS cache instance.
	synchronousRefresh bool          // Deprecated: No longer used.
}

// NewCachingProvider creates a CachingProvider with cache TTL and optional configurations.
// It automatically handles background refreshes to ensure fresh keys are available.
// Use the ProviderOption and CachingProviderOption functions to configure the provider.
// The cache TTL is set to 1 minute by default if not specified.
func NewCachingProvider(issuerURL *url.URL, cacheTTL time.Duration, opts ...interface{}) *CachingProvider {
	if cacheTTL <= 0 {
		cacheTTL = time.Minute // Default TTL if none is specified.
	}

	cp := &CachingProvider{
		Provider: Provider{
			IssuerURL: issuerURL,
			Client:    http.DefaultClient,
		},
		CacheTTL: cacheTTL,
	}

	for _, opt := range opts {
		switch o := opt.(type) {
		case ProviderOption:
			o(&cp.Provider)
		case CachingProviderOption:
			o(cp)
		default:
			panic(fmt.Sprintf("invalid option type: %T", o))
		}
	}

	return cp
}

// KeyFunc retrieves the cached JWKS or fetches and caches it if necessary.
// It ensures that the cache is refreshed within the refresh window to avoid key expiration issues.
// It returns an error if the JWKS URI is not set or if the keys cannot be fetched.
// It returns a jwk.Set instance that can be used to verify JWT tokens.
func (c *CachingProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	c.mu.Lock()
	if !c.initialized {
		c.once = sync.Once{} // Reset once if previous initialization failed
		c.mu.Unlock()

		var initErr error
		c.once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()

			c.cache = jwk.NewCache(ctx, jwk.WithRefreshWindow(c.CacheTTL*75/100)) // Refresh at 75% of TTL
			c.jwksURI, initErr = c.initJWKSURI(ctx)
			if initErr != nil || c.jwksURI == nil {
				return
			}

			minRefreshInterval := c.CacheTTL / 4
			if minRefreshInterval < time.Second {
				minRefreshInterval = time.Second
			}
			// Register the JWKS URI with the cache, ensuring periodic refreshes.
			if err := c.cache.Register(
				c.jwksURI.String(),
				jwk.WithMinRefreshInterval(minRefreshInterval),
				jwk.WithHTTPClient(c.Client),
			); err != nil {
				initErr = fmt.Errorf("cache registration failed: %w", err)
				return
			}

			// Perform the initial refresh to populate the cache.
			_, refreshErr := c.cache.Refresh(ctx, c.jwksURI.String())
			if refreshErr != nil {
				initErr = fmt.Errorf("initial cache refresh failed: %w", refreshErr)
				return
			}

			c.initialized = true
		})

		if initErr != nil {
			return nil, initErr
		}
	} else {
		c.mu.Unlock()
	}

	return jwk.NewCachedSet(c.cache, c.jwksURI.String()), nil
}

// initJWKSURI initializes and resolves the JWKS URI either from a custom URI or via OIDC discovery.
func (p *Provider) initJWKSURI(ctx context.Context) (*url.URL, error) {
	if p.CustomJWKSURI != nil {
		return p.CustomJWKSURI, nil
	}
	return jwksFromIssuerURL(ctx, p.IssuerURL, p.Client)
}

// jwksFromIssuerURL performs OIDC discovery to resolve the JWKS URI from the issuer's well-known configuration.
func jwksFromIssuerURL(ctx context.Context, issuerURL *url.URL, client *http.Client) (*url.URL, error) {
	if issuerURL == nil {
		return nil, fmt.Errorf("issuer URL is required")
	}
	wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, client, *issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve well-known endpoints: %w", err)
	}

	return url.Parse(wkEndpoints.JWKSURI)
}
