/*
Package jwks provides JWKS (JSON Web Key Set) fetching and caching for JWT validation.

This package implements providers that fetch public keys from OIDC identity providers
(like Auth0, Okta, etc.) to validate JWT signatures. It supports both synchronous
fetching and intelligent caching to reduce latency and API calls.

# Overview

JWKS providers handle the complexity of:
  - OIDC discovery (fetching .well-known/openid-configuration)
  - Fetching JWKS from the provider's jwks_uri
  - Caching keys with configurable TTL
  - Thread-safe concurrent access
  - Automatic cache refresh

# Provider vs CachingProvider

Provider: Simple JWKS fetcher without caching
  - Fetches JWKS on every request
  - Suitable for development/testing
  - No memory overhead

CachingProvider: Production-ready with intelligent caching
  - Caches JWKS with configurable TTL (default: 15 minutes)
  - Thread-safe with proper locking
  - Prevents thundering herd on cache refresh
  - Recommended for production use

# Basic Usage with Provider

Simple provider that fetches JWKS on every request:

	import (
	    "github.com/auth0/go-jwt-middleware/v3/jwks"
	    "github.com/auth0/go-jwt-middleware/v3/validator"
	)

	issuerURL, _ := url.Parse("https://auth.example.com/")

	// Create simple provider
	provider, err := jwks.NewProvider(
	    jwks.WithIssuerURL(issuerURL),
	)
	if err != nil {
	    log.Fatal(err)
	}

	// Use with validator
	v, err := validator.New(
	    validator.WithKeyFunc(provider.KeyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer(issuerURL.String()),
	    validator.WithAudience("my-api"),
	)

# Production Usage with CachingProvider

Recommended for production with intelligent caching:

	// Create caching provider with 5-minute TTL
	provider, err := jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	    jwks.WithCacheTTL(5*time.Minute),
	)
	if err != nil {
	    log.Fatal(err)
	}

	// Use with validator (same interface as Provider)
	v, err := validator.New(
	    validator.WithKeyFunc(provider.KeyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuer(issuerURL.String()),
	    validator.WithAudience("my-api"),
	)

# Custom JWKS URI

Skip OIDC discovery and use a custom JWKS URI:

	jwksURI, _ := url.Parse("https://example.com/custom/.well-known/jwks.json")

	provider, err := jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	    jwks.WithCustomJWKSURI(jwksURI),
	    jwks.WithCacheTTL(10*time.Minute),
	)

# Custom HTTP Client

Configure timeouts, proxies, or custom transport:

	client := &http.Client{
	    Timeout: 10 * time.Second,
	    Transport: &http.Transport{
	        MaxIdleConns:        100,
	        MaxIdleConnsPerHost: 10,
	    },
	}

	provider, err := jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	    jwks.WithCustomClient(client),
	)

# Custom Cache Implementation

Implement your own cache (e.g., Redis-backed):

	type RedisCache struct {
	    client *redis.Client
	}

	func (c *RedisCache) Get(ctx context.Context, jwksURI string) (jwks.KeySet, error) {
	    // Implement Redis caching logic
	}

	provider, err := jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	    jwks.WithCache(customCache),
	)

# Cache Behavior

The default jwxCache implementation provides:

1. Thread-safe access: Uses read/write locks for concurrent requests

2. Lazy fetching: Only fetches when cache is empty or expired

 3. Single-flight fetching: Only one goroutine fetches per URI,
    others wait for the result (prevents thundering herd)

4. Automatic expiration: Keys expire after configured TTL

5. No background refresh: Fetches only when needed (on-demand)

# OIDC Discovery

When using WithIssuerURL without WithCustomJWKSURI, the provider
automatically discovers the JWKS URI using the OIDC well-known endpoint:

	https://issuer.example.com/.well-known/openid-configuration

The jwks_uri field from the response is used to fetch keys.

# Error Handling

	provider, err := jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	)
	if err != nil {
	    // Configuration error
	}

	// During validation
	keys, err := provider.KeyFunc(ctx)
	if err != nil {
	    // JWKS fetch failed (network error, invalid response, etc.)
	}

# Performance Considerations

CachingProvider with default settings (15-minute TTL):
  - First request: ~100-500ms (OIDC discovery + JWKS fetch)
  - Cached requests: <1ms (memory lookup)
  - Cache refresh: ~50-200ms (JWKS fetch only, no discovery)

Recommended TTL values:
  - Development: 1-5 minutes (faster key rotation testing)
  - Production: 15-60 minutes (balance between freshness and performance)
  - High-security: 5-15 minutes (faster revocation detection)

# Security Notes

1. Always use HTTPS URLs for issuerURL and JWKS URIs
2. Consider shorter TTLs for high-security applications
3. The cache does not validate key expiration (jwx handles this)
4. Provider fetches all keys in the JWKS (jwx selects the right one)
*/
package jwks
