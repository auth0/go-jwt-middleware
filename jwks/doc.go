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

# Choosing the Right Provider

Provider: Simple JWKS fetcher without caching
  - Fetches JWKS on every request
  - Suitable for development/testing
  - No memory overhead
  - Use for: Testing, single-use scenarios

CachingProvider: Production-ready with intelligent caching
  - Caches JWKS with configurable TTL (default: 15 minutes)
  - Thread-safe with proper locking
  - Proactive background refresh at 80% TTL
  - OIDC discovery cached once (until application restart)
  - Use for: Single issuer production applications

MultiIssuerProvider: Multi-tenant with dynamic JWKS routing
  - Automatically routes JWKS requests per issuer
  - Lazy loading - creates providers on-demand
  - LRU eviction for memory management (optional)
  - Custom cache support (e.g., Redis)
  - OIDC discovery cached per issuer (until application restart)
  - Use for: Multi-tenant SaaS, multiple Auth0 tenants, dynamic issuers

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

Note: OIDC discovery (fetching .well-known/openid-configuration) is performed
once per provider and cached for the lifetime of the application. The discovered
JWKS URI is stored and will not be updated until the application restarts.
If you need dynamic JWKS URI updates, use WithCustomJWKSURI or restart the application.

# Custom HTTP Client

Configure timeouts, proxies, or custom transport:

	customClient := &http.Client{
	    Timeout: 10 * time.Second,
	    Transport: myCustomTransport,
	}

	provider, _ := jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	    jwks.WithCustomClient(customClient),
	)

# Cache-Control Header Support

The SDK respects HTTP Cache-Control headers from JWKS responses only when the
configured TTL is shorter than the max-age value. This allows extending cache
time when the provider permits longer caching.

Behavior:
  - Uses Cache-Control max-age only when configured TTL < max-age
  - Allows providers to extend cache time for stable keys
  - Configured TTL acts as a minimum refresh interval
  - Validates max-age is reasonable (1 second to 7 days)

Example:

	// Configure 15-minute default TTL
	provider, _ := jwks.NewCachingProvider(
	    jwks.WithIssuerURL(issuerURL),
	    jwks.WithCacheTTL(15*time.Minute),
	)

	// Case 1: JWKS response "Cache-Control: max-age=3600" (1 hour)
	// → Uses 1 hour (configured TTL 15 min < max-age 1 hour, so uses max-age)

	// Case 2: JWKS response "Cache-Control: max-age=300" (5 minutes)
	// → Uses 15 minutes (configured TTL 15 min > max-age 5 min, so uses configured TTL)

	// Case 3: JWKS response "Cache-Control: max-age=86400000"
	// → Rejects (exceeds 7-day max), uses 15 min configured TTL

	// Case 4: No Cache-Control header
	// → Uses 15-minute configured TTL

Security limits:
  - Minimum: 1 second (prevents rapid refresh attacks)
  - Maximum: 7 days (prevents indefinite caching)
  - Final TTL: max-age if (configured TTL < max-age), otherwise configured TTL

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

# Multi-Issuer Support

For applications accepting JWTs from multiple issuers (multi-tenant SaaS,
multiple Auth0 tenants, or domain migrations):

Basic multi-issuer setup:

	// Create multi-issuer provider
	provider, err := jwks.NewMultiIssuerProvider(
	    jwks.WithMultiIssuerCacheTTL(5*time.Minute),
	)

	// Use with multiple issuers
	v, err := validator.New(
	    validator.WithKeyFunc(provider.KeyFunc),
	    validator.WithAlgorithm(validator.RS256),
	    validator.WithIssuers([]string{
	        "https://tenant1.auth0.com/",
	        "https://tenant2.auth0.com/",
	        "https://tenant3.auth0.com/",
	    }),
	    validator.WithAudience("my-api"),
	)

The MultiIssuerProvider:
  - Extracts validated issuer from request context
  - Routes JWKS requests to the correct issuer-specific provider
  - Creates providers lazily (on first request per issuer)
  - Caches providers for future requests
  - Thread-safe with double-checked locking

# Large-Scale Multi-Tenant (100+ Tenants)

For applications with many tenants, use Redis and LRU eviction:

	// Create Redis cache
	redisCache := &RedisCache{
	    client: redis.NewClient(&redis.Options{
	        Addr: "localhost:6379",
	    }),
	    ttl: 5 * time.Minute,
	}

	// Configure with Redis and LRU
	provider, err := jwks.NewMultiIssuerProvider(
	    jwks.WithMultiIssuerCacheTTL(5*time.Minute),
	    jwks.WithMultiIssuerCache(redisCache),  // Share JWKS across instances
	    jwks.WithMaxProviders(1000),            // Limit to 1000 providers in memory
	)

Benefits of Redis + LRU for large scale:
  - JWKS data shared across multiple application instances
  - Reduced memory footprint per instance
  - Automatic TTL management via Redis
  - LRU eviction prevents unbounded memory growth
  - Handles thousands of tenants efficiently

# MultiIssuerProvider Options

Available configuration options:

	WithMultiIssuerCacheTTL(ttl time.Duration)
	    - JWKS cache refresh interval for all issuers
	    - Default: 15 minutes
	    - Recommended: 5-15 minutes

	WithMultiIssuerHTTPClient(client *http.Client)
	    - Custom HTTP client for all JWKS fetching
	    - Default: 30s timeout
	    - Use for: Custom timeouts, proxies, instrumentation

	WithMultiIssuerCache(cache Cache)
	    - Custom cache implementation (e.g., Redis)
	    - Default: In-memory per provider
	    - Use for: 100+ tenants, distributed caching

	WithMaxProviders(max int)
	    - Maximum number of issuer providers to cache
	    - Default: 100 (recommended for MCD scenarios)
	    - Set to 0 for unlimited
	    - Recommended: 500-1000 for large-scale apps
	    - LRU eviction removes least-recently-used providers

# When to Use MultiIssuerProvider vs CachingProvider

Use CachingProvider when:
  - You have a single OIDC issuer
  - All tokens come from one Auth0 tenant
  - Simpler configuration is preferred

Use MultiIssuerProvider when:
  - Multi-tenant SaaS application (each tenant has own issuer)
  - Multiple Auth0 tenants to support
  - Domain migration (old + new domains)
  - Dynamic issuer list from database
  - Enterprise with multiple identity providers

IMPORTANT: Always pair with correct validator option:
  - MultiIssuerProvider → validator.WithIssuers() or WithIssuersResolver()
  - CachingProvider → validator.WithIssuer() (single issuer only)

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
  - Proactive refresh: Triggered at 80% TTL, users experience <1ms

MultiIssuerProvider performance:
  - First request per issuer: ~100-500ms (creates provider + JWKS fetch)
  - Subsequent requests (same issuer): <1ms (cached provider)
  - Provider creation: Thread-safe with double-checked locking
  - With Redis cache: +1-5ms per request (Redis round-trip)
  - LRU eviction: O(1) operation, no performance impact

Recommended TTL values:
  - Development: 1-5 minutes (faster key rotation testing)
  - Production: 15-60 minutes (balance between freshness and performance)
  - High-security: 5-15 minutes (faster revocation detection)
  - Multi-tenant: 5-15 minutes (good balance for many issuers)

Scaling guidelines:
  - < 10 issuers: Use MultiIssuerProvider with default in-memory cache
  - 10-100 issuers: Default settings (maxProviders=100) are optimal
  - 100-1000 issuers: Use Redis cache, consider WithMaxProviders(500)
  - 1000+ issuers: Use Redis cache + WithMaxProviders(1000), monitor metrics

# Security Notes

1. Always use HTTPS URLs for issuerURL and JWKS URIs
2. Consider shorter TTLs for high-security applications
3. The cache does not validate key expiration (jwx handles this)
4. Provider fetches all keys in the JWKS (jwx selects the right one)
5. MultiIssuerProvider validates issuer BEFORE fetching JWKS (prevents SSRF)
6. Use validator.WithIssuers() to explicitly allowlist issuers
7. For dynamic issuers, implement proper authorization in your resolver
8. Monitor provider count in multi-tenant apps to detect abuse

# Thread Safety

All providers are thread-safe and can be shared across goroutines:
  - Provider: Thread-safe, no shared state
  - CachingProvider: Thread-safe with RWMutex, proactive refresh prevents contention
  - MultiIssuerProvider: Thread-safe with double-checked locking pattern

Safe to use the same provider instance across all requests.

# Examples

See the examples directory for complete working code:
  - examples/http-jwks-example: Basic CachingProvider setup
  - examples/http-multi-issuer-example: MultiIssuerProvider with static list
  - examples/http-multi-issuer-redis-example: Large-scale with Redis + LRU
  - examples/http-dynamic-issuer-example: Dynamic issuer resolution
*/
package jwks
