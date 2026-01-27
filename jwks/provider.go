package jwks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/auth0/go-jwt-middleware/v3/internal/oidc"
)

// KeySet represents a set of JSON Web Keys.
// This interface abstracts the underlying JWKS implementation.
type KeySet any

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

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be jwk.Set.
func (p *Provider) KeyFunc(ctx context.Context) (any, error) {
	jwksURI := p.CustomJWKSURI
	if jwksURI == nil {
		// Fetch OIDC discovery metadata with MCD double-validation
		wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(
			ctx,
			p.Client,
			*p.IssuerURL,
			p.IssuerURL.String(),
		)
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
	set        jwk.Set
	expiresAt  time.Time
	refreshAt  time.Time   // Proactive refresh threshold (80% of TTL)
	refreshing atomic.Bool // Prevents multiple background refreshes
	fetchMu    sync.Mutex  // Ensures only one fetch per URI at a time
}

func (c *jwxCache) Get(ctx context.Context, jwksURI string) (KeySet, error) {
	now := time.Now()

	// Fast path: check if we have a valid cached entry
	c.cacheMu.RLock()
	cached, exists := c.cache[jwksURI]
	if exists && now.Before(cached.expiresAt) {
		// Cache hit - read while holding lock to avoid race
		result := cached.set
		shouldRefresh := now.After(cached.refreshAt)
		c.cacheMu.RUnlock()

		// Trigger background refresh if in refresh window and not already refreshing
		if shouldRefresh && cached.refreshing.CompareAndSwap(false, true) {
			go c.backgroundRefresh(jwksURI, cached)
		}

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
	set, cacheTTL, err := c.fetchWithCacheControl(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("could not fetch JWKS: %w", err)
	}

	// Use Cache-Control max-age only when configured TTL is shorter
	// This allows extending cache time when the provider permits longer caching
	effectiveTTL := c.refreshTTL
	if cacheTTL > 0 && c.refreshTTL < cacheTTL {
		effectiveTTL = cacheTTL // Configured TTL is shorter - use the longer max-age
	}
	// Otherwise use configured TTL (either no Cache-Control, it's shorter, or invalid)

	// Update cache - must hold cacheMu to synchronize with readers in fast path
	c.cacheMu.Lock()
	cached.set = set
	cached.expiresAt = now.Add(effectiveTTL)
	cached.refreshAt = now.Add(effectiveTTL * 4 / 5) // Refresh at 80% of TTL
	c.cacheMu.Unlock()

	return set, nil
}

// fetchWithCacheControl fetches JWKS and extracts TTL from Cache-Control headers.
// Returns the JWKS set, the TTL (or 0 if not present), and any error.
func (c *jwxCache) fetchWithCacheControl(ctx context.Context, jwksURI string) (jwk.Set, time.Duration, error) {
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute HTTP request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("request returned status %d, expected 200", resp.StatusCode)
	}

	// Parse Cache-Control header for max-age directive
	var cacheTTL time.Duration
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "" {
		cacheTTL = parseCacheControl(cacheControl)
	}

	// Limit response body size to prevent memory exhaustion attacks
	// 1MB is generous for JWKS (typically <10KB)
	limitedBody := io.LimitReader(resp.Body, 1*1024*1024)

	// Parse JWKS from response body
	set, err := jwk.ParseReader(limitedBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return set, cacheTTL, nil
}

// parseCacheControl extracts max-age from Cache-Control header with security validation.
// Returns 0 if max-age is not present, invalid, or unreasonable.
//
// Security limits:
//   - Minimum: 1 second (prevents rapid refresh attacks)
//   - Maximum: 7 days (prevents indefinite caching)
//   - Only accepts positive integers
func parseCacheControl(cacheControl string) time.Duration {
	const (
		maxAgePrefix = "max-age="
		minTTL       = 1 * time.Second    // Prevent rapid refresh attacks
		maxTTL       = 7 * 24 * time.Hour // Prevent indefinite caching (7 days)
	)

	// Split by comma to handle multiple directives
	// Handles: "max-age=3600", "public, max-age=3600", "max-age=3600, must-revalidate"
	directives := strings.Split(cacheControl, ",")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, maxAgePrefix) {
			ageStr := strings.TrimPrefix(directive, maxAgePrefix)
			seconds, err := strconv.ParseInt(ageStr, 10, 64)
			if err != nil || seconds <= 0 {
				continue // Invalid format or negative value
			}

			ttl := time.Duration(seconds) * time.Second

			// Validate TTL is within reasonable bounds
			if ttl < minTTL || ttl > maxTTL {
				return 0 // Reject unreasonable values
			}

			return ttl
		}
	}

	return 0 // No valid max-age directive found
}

// backgroundRefresh refreshes JWKS in the background without blocking requests.
// This prevents cache expiry from blocking requests by proactively refreshing
// when the cache reaches 80% of its TTL.
func (c *jwxCache) backgroundRefresh(jwksURI string, cached *cachedJWKS) {
	defer cached.refreshing.Store(false)

	// Use a fresh context with timeout for background refresh
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Fetch fresh JWKS
	set, cacheTTL, err := c.fetchWithCacheControl(ctx, jwksURI)
	if err != nil {
		return
	}

	// Use Cache-Control max-age only when configured TTL is shorter
	effectiveTTL := c.refreshTTL
	if cacheTTL > 0 && c.refreshTTL < cacheTTL {
		effectiveTTL = cacheTTL // Configured TTL is shorter - use the longer max-age
	}

	// Update cache with fresh data
	now := time.Now()
	c.cacheMu.Lock()
	cached.set = set
	cached.expiresAt = now.Add(effectiveTTL)
	cached.refreshAt = now.Add(effectiveTTL * 4 / 5) // Refresh at 80% of TTL
	c.cacheMu.Unlock()
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

// discoverJWKSURI discovers the JWKS URI from the well-known endpoint.
// Uses sync.Once to ensure discovery only happens once, improving performance.
// Performs MCD double-validation: ensures metadata's issuer matches expected issuer.
func (c *CachingProvider) discoverJWKSURI(ctx context.Context) error {
	var discoveryErr error

	c.jwksURIOnce.Do(func() {
		// Fetch OIDC discovery metadata with MCD double-validation
		wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(
			ctx,
			c.httpClient,
			*c.issuerURL,
			c.issuerURL.String(),
		)
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
func (c *CachingProvider) KeyFunc(ctx context.Context) (any, error) {
	// Get JWKS URI (with lazy discovery and caching)
	jwksURI, err := c.getJWKSURI(ctx)
	if err != nil {
		return nil, err
	}

	// Get from cache (implements automatic refresh)
	return c.cache.Get(ctx, jwksURI)
}
