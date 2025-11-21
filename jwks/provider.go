package jwks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/auth0/go-jwt-middleware/v3/internal/oidc"
)

// KeySet represents a set of JSON Web Keys.
// This interface abstracts the underlying JWKS implementation.
type KeySet interface{}

// Cache defines the interface for JWKS caching implementations.
// This abstraction allows swapping the underlying cache provider.
type Cache interface {
	// Get retrieves a JWKS from the cache or fetches it if not cached.
	Get(ctx context.Context, jwksURI string) (KeySet, error)
}

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
type ProviderOption func(*Provider) error

// NewProvider builds and returns a new *Provider.
// Required options:
//   - WithIssuerURL: OIDC issuer URL for JWKS discovery
//
// Optional options:
//   - WithCustomJWKSURI: Custom JWKS URI (skips discovery)
//   - WithCustomClient: Custom HTTP client
//
// Example:
//
//	provider, err := jwks.NewProvider(
//	    jwks.WithIssuerURL(issuerURL),
//	    jwks.WithCustomClient(myHTTPClient),
//	)
func NewProvider(opts ...ProviderOption) (*Provider, error) {
	p := &Provider{
		Client: &http.Client{Timeout: 30 * time.Second},
	}

	// Apply all options
	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Validate required fields
	if p.IssuerURL == nil {
		return nil, fmt.Errorf("issuer URL is required (use WithIssuerURL)")
	}

	return p, nil
}

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

// WithCustomJWKSURI will set a custom JWKS URI on the *Provider and
// call this directly inside the keyFunc in order to fetch the JWKS,
// skipping the oidc.GetWellKnownEndpointsFromIssuerURL call.
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(p *Provider) error {
		if jwksURI == nil {
			return fmt.Errorf("custom JWKS URI cannot be nil")
		}
		p.CustomJWKSURI = jwksURI
		return nil
	}
}

// WithCustomClient will set a custom *http.Client on the *Provider
func WithCustomClient(c *http.Client) ProviderOption {
	return func(p *Provider) error {
		if c == nil {
			return fmt.Errorf("HTTP client cannot be nil")
		}
		p.Client = c
		return nil
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

// jwxCache wraps jwx's Cache to implement our Cache interface with proper concurrency handling.
// This adapter allows us to swap out the underlying cache implementation.
type jwxCache struct {
	httpClient *http.Client
	cacheMu    sync.RWMutex
	cache      map[string]*cachedJWKS
	refreshTTL time.Duration
}

type cachedJWKS struct {
	set       jwk.Set
	expiresAt time.Time
	fetchMu   sync.Mutex // Ensures only one fetch per URI at a time
}

func (c *jwxCache) Get(ctx context.Context, jwksURI string) (KeySet, error) {
	now := time.Now()

	// Fast path: check if we have a valid cached entry
	c.cacheMu.RLock()
	cached, exists := c.cache[jwksURI]
	if exists && now.Before(cached.expiresAt) {
		// Cache hit - read while holding lock to avoid race
		result := cached.set
		c.cacheMu.RUnlock()
		return result, nil
	}
	c.cacheMu.RUnlock()

	// Cache miss or expired - need to fetch
	// Ensure the entry exists before we lock it
	if !exists {
		c.cacheMu.Lock()
		cached, exists = c.cache[jwksURI]
		if !exists {
			cached = &cachedJWKS{}
			c.cache[jwksURI] = cached
		}
		c.cacheMu.Unlock()
	}

	// Lock the specific URI's fetch mutex to prevent concurrent fetches
	cached.fetchMu.Lock()
	defer cached.fetchMu.Unlock()

	// Double-check after acquiring fetch lock - another goroutine may have fetched
	// Must also check with cacheMu.RLock to avoid race with writes
	c.cacheMu.RLock()
	isValid := now.Before(cached.expiresAt)
	result := cached.set
	c.cacheMu.RUnlock()

	if isValid {
		return result, nil
	}

	// Fetch fresh JWKS from network
	set, err := jwk.Fetch(ctx, jwksURI, jwk.WithHTTPClient(c.httpClient))
	if err != nil {
		return nil, fmt.Errorf("could not fetch JWKS: %w", err)
	}

	// Update cache - must hold cacheMu to synchronize with readers in fast path
	c.cacheMu.Lock()
	cached.set = set
	cached.expiresAt = now.Add(c.refreshTTL)
	c.cacheMu.Unlock()

	return set, nil
}

// CachingProvider handles getting JWKS from the specified IssuerURL
// and caching them using an underlying cache implementation.
// It exposes KeyFunc which adheres to the keyFunc signature that the Validator requires.
// The cache automatically handles background refresh and concurrency.
type CachingProvider struct {
	cache      Cache
	issuerURL  *url.URL
	httpClient *http.Client

	// JWKS URI discovery - lazily initialized and cached
	jwksURIMu   sync.Mutex
	jwksURI     string
	jwksURIOnce sync.Once
}

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

// NewCachingProvider builds and returns a new CachingProvider.
// The cache automatically handles background refresh.
//
// Accepts both ProviderOption and CachingProviderOption types, so you can use
// common options like WithIssuerURL, WithCustomJWKSURI, and WithCustomClient
// without any wrapper.
//
// Required options:
//   - WithIssuerURL: OIDC issuer URL for JWKS discovery
//
// Optional options:
//   - WithCacheTTL: Cache refresh interval (default: 15 minutes)
//   - WithCustomJWKSURI: Custom JWKS URI (skips discovery)
//   - WithCustomClient: Custom HTTP client
//   - WithCache: Custom cache implementation
//
// Example:
//
//	provider, err := jwks.NewCachingProvider(
//	    jwks.WithIssuerURL(issuerURL),        // ProviderOption - works directly!
//	    jwks.WithCacheTTL(5*time.Minute),     // CachingProviderOption
//	    jwks.WithCustomClient(myHTTPClient),  // ProviderOption - works directly!
//	)
//
// Returns an error if the cache cannot be initialized.
func NewCachingProvider(opts ...any) (*CachingProvider, error) {
	config := &cachingProviderConfig{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cacheTTL:   15 * time.Minute, // Default to 15 minutes
	}

	// Apply all options with type switching to support both option types
	for _, opt := range opts {
		switch v := opt.(type) {
		case CachingProviderOption:
			// Native CachingProviderOption - apply directly
			if err := v(config); err != nil {
				return nil, fmt.Errorf("invalid option: %w", err)
			}
		case ProviderOption:
			// ProviderOption - convert to CachingProviderOption
			tempProvider := &Provider{}
			if err := v(tempProvider); err != nil {
				return nil, fmt.Errorf("invalid option: %w", err)
			}

			// Transfer values from Provider to cachingProviderConfig
			if tempProvider.IssuerURL != nil {
				config.issuerURL = tempProvider.IssuerURL
			}
			if tempProvider.CustomJWKSURI != nil {
				config.customJWKSURI = tempProvider.CustomJWKSURI
			}
			if tempProvider.Client != nil {
				config.httpClient = tempProvider.Client
			}
		default:
			return nil, fmt.Errorf("invalid option type: %T (must be ProviderOption or CachingProviderOption)", opt)
		}
	}

	// Validate required fields
	if config.issuerURL == nil {
		return nil, fmt.Errorf("issuer URL is required (use WithIssuerURL)")
	}

	cp := &CachingProvider{
		issuerURL:  config.issuerURL,
		httpClient: config.httpClient,
	}

	// Pre-set JWKS URI if custom URI provided
	if config.customJWKSURI != nil {
		cp.jwksURI = config.customJWKSURI.String()
	}

	// Use custom cache if provided, otherwise create default jwx cache
	if config.cache != nil {
		cp.cache = config.cache
	} else {
		// Initialize default jwx cache adapter with simple in-memory caching
		cp.cache = &jwxCache{
			httpClient: config.httpClient,
			cache:      make(map[string]*cachedJWKS),
			refreshTTL: config.cacheTTL,
		}
	}

	return cp, nil
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

// discoverJWKSURI discovers the JWKS URI from the well-known endpoint.
// Uses sync.Once to ensure discovery only happens once, improving performance.
func (c *CachingProvider) discoverJWKSURI(ctx context.Context) error {
	var discoveryErr error

	c.jwksURIOnce.Do(func() {
		wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, c.httpClient, *c.issuerURL)
		if err != nil {
			discoveryErr = fmt.Errorf("failed to discover JWKS URI: %w", err)
			return
		}

		c.jwksURIMu.Lock()
		c.jwksURI = wkEndpoints.JWKSURI
		c.jwksURIMu.Unlock()
	})

	return discoveryErr
}

// getJWKSURI returns the JWKS URI, discovering it if necessary.
func (c *CachingProvider) getJWKSURI(ctx context.Context) (string, error) {
	// Fast path: URI already set (custom URI or already discovered)
	c.jwksURIMu.Lock()
	uri := c.jwksURI
	c.jwksURIMu.Unlock()

	if uri != "" {
		return uri, nil
	}

	// Slow path: discover URI
	if err := c.discoverJWKSURI(ctx); err != nil {
		return "", err
	}

	c.jwksURIMu.Lock()
	uri = c.jwksURI
	c.jwksURIMu.Unlock()

	return uri, nil
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be jwk.Set.
//
// This method is thread-safe and optimized for concurrent access.
func (c *CachingProvider) KeyFunc(ctx context.Context) (interface{}, error) {
	// Get JWKS URI (with lazy discovery and caching)
	jwksURI, err := c.getJWKSURI(ctx)
	if err != nil {
		return nil, err
	}

	// Get from cache (implements automatic refresh)
	return c.cache.Get(ctx, jwksURI)
}
