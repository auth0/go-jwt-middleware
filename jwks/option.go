package jwks

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ============================================================================
// Provider Options
// ============================================================================

// ProviderOption is how options for the Provider are set up.
type ProviderOption func(*Provider) error

// WithIssuerURL sets the OIDC issuer URL for JWKS discovery.
// This is a required option.
//
// The issuer URL is used to discover the JWKS endpoint via the
// .well-known/openid-configuration endpoint.
func WithIssuerURL(issuerURL *url.URL) ProviderOption {
	return func(p *Provider) error {
		if issuerURL == nil {
			return fmt.Errorf("issuer URL cannot be nil")
		}
		p.IssuerURL = issuerURL
		return nil
	}
}

// WithCustomJWKSURI sets a custom JWKS URI for the Provider.
// When set, the Provider will fetch JWKS directly from this URI,
// skipping the OIDC discovery process (.well-known/openid-configuration).
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(p *Provider) error {
		if jwksURI == nil {
			return fmt.Errorf("custom JWKS URI cannot be nil")
		}
		p.CustomJWKSURI = jwksURI
		return nil
	}
}

// WithCustomClient sets a custom HTTP client for the Provider.
// If not specified, a default client with 30s timeout is used.
func WithCustomClient(c *http.Client) ProviderOption {
	return func(p *Provider) error {
		if c == nil {
			return fmt.Errorf("HTTP client cannot be nil")
		}
		p.Client = c
		return nil
	}
}

// ============================================================================
// CachingProvider Options
// ============================================================================

// CachingProviderOption is how options for the CachingProvider are set up.
// These options are specific to CachingProvider (e.g., cache configuration).
type CachingProviderOption func(*cachingProviderConfig) error

// cachingProviderConfig holds internal configuration for creating a CachingProvider.
type cachingProviderConfig struct {
	issuerURL     *url.URL
	customJWKSURI *url.URL
	httpClient    *http.Client
	cacheTTL      time.Duration
	cache         Cache // Optional: custom cache implementation
}

// WithCacheTTL sets the cache refresh interval for the CachingProvider.
// If not specified, defaults to 15 minutes.
//
// The TTL determines the minimum interval between JWKS refreshes.
func WithCacheTTL(ttl time.Duration) CachingProviderOption {
	return func(c *cachingProviderConfig) error {
		if ttl < 0 {
			return fmt.Errorf("cache TTL cannot be negative")
		}
		if ttl == 0 {
			ttl = 15 * time.Minute
		}
		c.cacheTTL = ttl
		return nil
	}
}

// WithCache sets a custom Cache implementation for the CachingProvider.
// This allows users to provide their own caching strategy (e.g., Redis-backed cache).
//
// Example:
//
//	customCache := &MyRedisCache{...}
//	provider, err := jwks.NewCachingProvider(
//	    jwks.WithIssuerURL(issuerURL),
//	    jwks.WithCache(customCache),
//	)
func WithCache(cache Cache) CachingProviderOption {
	return func(c *cachingProviderConfig) error {
		if cache == nil {
			return fmt.Errorf("cache cannot be nil")
		}
		c.cache = cache
		return nil
	}
}

// ============================================================================
// MultiIssuerProvider Options
// ============================================================================

// MultiIssuerProviderOption is how options for MultiIssuerProvider are set up.
type MultiIssuerProviderOption func(*multiIssuerConfig) error

// multiIssuerConfig holds internal configuration for creating a MultiIssuerProvider.
type multiIssuerConfig struct {
	cacheTTL     time.Duration
	httpClient   *http.Client
	cache        Cache // Optional: custom cache implementation
	maxProviders int   // Maximum number of cached providers (0 = unlimited)
}

// WithMultiIssuerCacheTTL sets the cache refresh interval for all per-issuer providers.
// If not specified, defaults to 15 minutes.
//
// The TTL determines the minimum interval between JWKS refreshes for each issuer.
func WithMultiIssuerCacheTTL(ttl time.Duration) MultiIssuerProviderOption {
	return func(c *multiIssuerConfig) error {
		if ttl < 0 {
			return fmt.Errorf("cache TTL cannot be negative")
		}
		if ttl == 0 {
			ttl = 15 * time.Minute
		}
		c.cacheTTL = ttl
		return nil
	}
}

// WithMultiIssuerHTTPClient sets a custom HTTP client for all per-issuer providers.
// If not specified, a default client with 30s timeout is used.
//
// Example:
//
//	customClient := &http.Client{
//	    Timeout: 10 * time.Second,
//	    Transport: myCustomTransport,
//	}
//	provider, _ := jwks.NewMultiIssuerProvider(
//	    jwks.WithMultiIssuerHTTPClient(customClient),
//	)
func WithMultiIssuerHTTPClient(client *http.Client) MultiIssuerProviderOption {
	return func(c *multiIssuerConfig) error {
		if client == nil {
			return fmt.Errorf("HTTP client cannot be nil")
		}
		c.httpClient = client
		return nil
	}
}

// WithMultiIssuerCache sets a custom Cache implementation for all per-issuer providers.
// This allows users to provide their own caching strategy (e.g., Redis-backed cache)
// that will be used across all issuers.
//
// RECOMMENDED: Use this option when working with 100+ tenants/issuers to avoid memory
// issues with the default in-memory cache. A distributed cache like Redis allows you
// to share JWKS data across multiple application instances and provides better memory
// management for large-scale multi-tenant applications.
//
// Example:
//
//	customCache := &MyRedisCache{...}
//	provider, _ := jwks.NewMultiIssuerProvider(
//	    jwks.WithMultiIssuerCache(customCache),
//	)
func WithMultiIssuerCache(cache Cache) MultiIssuerProviderOption {
	return func(c *multiIssuerConfig) error {
		if cache == nil {
			return fmt.Errorf("cache cannot be nil")
		}
		c.cache = cache
		return nil
	}
}

// WithMaxProviders sets the maximum number of issuer providers to cache in memory.
// When the limit is reached, the least-recently-used provider will be evicted.
// Default is 100 providers (recommended for MCD scenarios). Set to 0 for unlimited.
//
// RECOMMENDED: For applications with 1000+ dynamic issuers, set this to a reasonable
// limit (e.g., 500-1000) to prevent unbounded memory growth.
//
// Example:
//
//	provider, _ := jwks.NewMultiIssuerProvider(
//	    jwks.WithMaxProviders(1000), // Keep max 1000 providers in memory
//	    jwks.WithMultiIssuerCache(redisCache),
//	)
func WithMaxProviders(maxProviders int) MultiIssuerProviderOption {
	return func(c *multiIssuerConfig) error {
		if maxProviders < 0 {
			return fmt.Errorf("max providers cannot be negative")
		}
		c.maxProviders = maxProviders
		return nil
	}
}
