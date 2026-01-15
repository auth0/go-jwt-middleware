package jwks

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/validator"
)

// MultiIssuerProvider handles JWKS for multiple issuers dynamically.
// It creates and caches per-issuer JWKS providers on-demand, automatically
// routing requests to the correct issuer based on the validated issuer in the context.
//
// This provider is designed to work with both static and dynamic issuer lists:
//   - Static: Use with validator.WithIssuers() for a fixed list of allowed issuers
//   - Dynamic: Use with validator.WithIssuersResolver() for runtime issuer determination
//
// Thread-safe for concurrent access across multiple requests.
//
// IMPORTANT: For applications with 100+ tenants/issuers, it is strongly recommended
// to use a custom cache implementation (e.g., Redis) via WithMultiIssuerCache() instead
// of the default in-memory cache. The default in-memory cache creates a separate cached
// JWKS entry per issuer, which can consume significant memory and may lead to performance
// issues with a large number of tenants.
//
// Example usage:
//
//	provider, _ := jwks.NewMultiIssuerProvider(
//	    jwks.WithMultiIssuerCacheTTL(10*time.Minute),
//	)
//
//	validator, _ := validator.New(
//	    validator.WithKeyFunc(provider.KeyFunc),
//	    validator.WithAlgorithm(validator.RS256),
//	    validator.WithIssuers([]string{
//	        "https://tenant1.auth0.com/",
//	        "https://tenant2.auth0.com/",
//	    }),
//	    validator.WithAudience("https://api.example.com"),
//	)
type MultiIssuerProvider struct {
	mu           sync.RWMutex
	providers    map[string]*providerEntry
	lruList      *list.List // LRU list for eviction
	maxProviders int        // Maximum number of cached providers (0 = unlimited)
	cacheTTL     time.Duration
	httpClient   *http.Client
	cache        Cache // Optional: custom cache shared by all issuers
}

// providerEntry wraps a CachingProvider with metadata for LRU tracking
type providerEntry struct {
	provider   *CachingProvider
	lruElement *list.Element // Reference to position in LRU list
	lastUsed   time.Time
	issuer     string
}

// NewMultiIssuerProvider creates a new MultiIssuerProvider.
// This provider automatically routes JWKS requests to the correct issuer
// based on the validated issuer stored in the request context.
//
// Optional options:
//   - WithMultiIssuerCacheTTL: Cache refresh interval (default: 15 minutes)
//   - WithMultiIssuerHTTPClient: Custom HTTP client (default: 30s timeout)
//   - WithMultiIssuerCache: Custom cache implementation (e.g., Redis)
//   - WithMaxProviders: Maximum number of cached providers (default: unlimited)
//
// Example:
//
//	provider, err := jwks.NewMultiIssuerProvider(
//	    jwks.WithMultiIssuerCacheTTL(10*time.Minute),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewMultiIssuerProvider(opts ...MultiIssuerProviderOption) (*MultiIssuerProvider, error) {
	config := &multiIssuerConfig{
		cacheTTL:     15 * time.Minute, // Default to 15 minutes
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		maxProviders: 0, // Default: unlimited
	}

	// Apply all options
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	return &MultiIssuerProvider{
		providers:    make(map[string]*providerEntry),
		lruList:      list.New(),
		maxProviders: config.maxProviders,
		cacheTTL:     config.cacheTTL,
		httpClient:   config.httpClient,
		cache:        config.cache,
	}, nil
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// It automatically routes JWKS requests to the correct issuer based on the
// validated issuer in the context.
//
// The issuer must be present in the context (set by the Validator after validation).
// If the issuer is not found, an error is returned.
//
// This method is thread-safe and optimized for concurrent access.
func (p *MultiIssuerProvider) KeyFunc(ctx context.Context) (any, error) {
	// Extract validated issuer from context
	issuer, ok := validator.IssuerFromContext(ctx)
	if !ok {
		return nil, errors.New("issuer not found in context - ensure validator validates issuer before calling keyFunc")
	}

	// Get or create provider for this issuer
	entry, err := p.getOrCreateProvider(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS provider for issuer %q: %w", issuer, err)
	}

	// Delegate to the issuer-specific provider
	return entry.provider.KeyFunc(ctx)
}

// getOrCreateProvider retrieves an existing provider for the issuer or creates a new one.
// Uses double-checked locking for optimal performance and thread safety.
// Implements LRU eviction when maxProviders limit is reached.
func (p *MultiIssuerProvider) getOrCreateProvider(issuer string) (*providerEntry, error) {
	// Fast path: check if provider exists (read lock)
	p.mu.RLock()
	entry, exists := p.providers[issuer]
	p.mu.RUnlock()

	if exists {
		// Update LRU position (requires write lock)
		p.mu.Lock()
		entry.lastUsed = time.Now()
		if entry.lruElement != nil {
			p.lruList.MoveToFront(entry.lruElement)
		}
		p.mu.Unlock()

		return entry, nil
	}

	// Slow path: create new provider (write lock)
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check: another goroutine may have created it while we waited for the lock
	entry, exists = p.providers[issuer]
	if exists {
		entry.lastUsed = time.Now()
		if entry.lruElement != nil {
			p.lruList.MoveToFront(entry.lruElement)
		}
		return entry, nil
	}

	// Check if we need to evict an entry (LRU eviction)
	if p.maxProviders > 0 && len(p.providers) >= p.maxProviders {
		p.evictLRU()
	}

	// Parse issuer URL
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL %q: %w", issuer, err)
	}

	// Create new CachingProvider for this issuer
	// Build options list
	opts := []any{
		WithIssuerURL(issuerURL),
		WithCacheTTL(p.cacheTTL),
		WithCustomClient(p.httpClient),
	}

	// Add custom cache if provided
	if p.cache != nil {
		opts = append(opts, WithCache(p.cache))
	}

	provider, err := NewCachingProvider(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider for issuer %q: %w", issuer, err)
	}

	// Create entry and add to LRU list
	entry = &providerEntry{
		provider: provider,
		lastUsed: time.Now(),
		issuer:   issuer,
	}
	entry.lruElement = p.lruList.PushFront(issuer)

	// Cache the provider for future requests
	p.providers[issuer] = entry

	return entry, nil
}

// evictLRU removes the least-recently-used provider from the cache.
// Must be called with write lock held.
func (p *MultiIssuerProvider) evictLRU() {
	if p.lruList.Len() == 0 {
		return
	}

	// Get the least-recently-used entry (back of list)
	oldest := p.lruList.Back()
	if oldest == nil {
		return
	}

	issuerToRemove := oldest.Value.(string)

	// Remove from map and list
	delete(p.providers, issuerToRemove)
	p.lruList.Remove(oldest)
}

// ProviderCount returns the number of issuer-specific providers currently cached.
// This is useful for monitoring memory usage in systems with many issuers.
//
// Example usage:
//
//	count := provider.ProviderCount()
//	log.Printf("Currently caching JWKS for %d issuers", count)
func (p *MultiIssuerProvider) ProviderCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.providers)
}
