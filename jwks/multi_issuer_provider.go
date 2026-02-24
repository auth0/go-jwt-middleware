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

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/auth0/go-jwt-middleware/v3/validator"
)

// IssuerKeyConfig configures key material for a specific issuer.
// Used with WithIssuerKeyConfig to support symmetric (HS256/HS384/HS512) issuers
// in MCD (Multiple Custom Domains) scenarios.
type IssuerKeyConfig struct {
	// Secret is the shared secret for symmetric algorithms (HS256/HS384/HS512).
	Secret []byte

	// Algorithm is the signature algorithm for this issuer.
	// Must be a symmetric algorithm (HS256, HS384, or HS512) when Secret is provided.
	Algorithm validator.SignatureAlgorithm

	// KeyID is an optional key ID (kid) for token header matching.
	// If set, it will be embedded in the JWK for kid-based key selection.
	KeyID string
}

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
// Example usage with asymmetric issuers (OIDC discovery):
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
//
// Example with mixed symmetric + asymmetric issuers:
//
//	provider, _ := jwks.NewMultiIssuerProvider(
//	    jwks.WithMultiIssuerCacheTTL(10*time.Minute),
//	    jwks.WithIssuerKeyConfig("https://symmetric.example.com/", jwks.IssuerKeyConfig{
//	        Secret:    []byte("shared-secret"),
//	        Algorithm: validator.HS256,
//	    }),
//	)
//
//	validator, _ := validator.New(
//	    validator.WithKeyFunc(provider.KeyFunc),
//	    validator.WithAlgorithms([]validator.SignatureAlgorithm{validator.RS256, validator.HS256}),
//	    validator.WithIssuers([]string{
//	        "https://tenant1.auth0.com/",        // RS256 via OIDC
//	        "https://symmetric.example.com/",     // HS256 via pre-shared secret
//	    }),
//	    validator.WithAudience("https://api.example.com"),
//	)
type MultiIssuerProvider struct {
	mu               sync.RWMutex
	providers        map[string]*providerEntry
	lruList          *list.List // LRU list for eviction
	maxProviders     int        // Maximum number of cached providers (0 = unlimited)
	cacheTTL         time.Duration
	httpClient       *http.Client
	cache            Cache                       // Optional: custom cache shared by all issuers
	staticKeys       map[string]jwk.Set          // Pre-built JWK sets for symmetric issuers
	issuerKeyConfigs map[string]*IssuerKeyConfig // Configuration for symmetric issuers
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
//   - WithMaxProviders: Maximum number of cached providers (default: 100)
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
		maxProviders: 100, // Default: 100 providers (recommended for MCD scenarios)
	}

	// Apply all options
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Build static JWK sets for symmetric issuers
	staticKeys := make(map[string]jwk.Set)
	issuerKeyConfigs := make(map[string]*IssuerKeyConfig)
	for issuer, keyConfig := range config.issuerKeyConfigs {
		keySet, err := buildSymmetricKeySet(keyConfig.Secret, keyConfig.Algorithm, keyConfig.KeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to build key set for issuer %q: %w", issuer, err)
		}
		staticKeys[issuer] = keySet
		issuerKeyConfigs[issuer] = keyConfig
	}

	return &MultiIssuerProvider{
		providers:        make(map[string]*providerEntry),
		lruList:          list.New(),
		maxProviders:     config.maxProviders,
		cacheTTL:         config.cacheTTL,
		httpClient:       config.httpClient,
		cache:            config.cache,
		staticKeys:       staticKeys,
		issuerKeyConfigs: issuerKeyConfigs,
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

	// Check for pre-built static key set (symmetric issuers)
	if keySet, ok := p.staticKeys[issuer]; ok {
		return keySet, nil
	}

	// Get or create provider for this issuer (asymmetric / OIDC discovery)
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

// ProviderCount returns the total number of issuers currently managed.
// This includes both OIDC providers (cached dynamically) and symmetric
// issuers (configured via WithIssuerKeyConfig).
//
// This is useful for monitoring memory usage in systems with many issuers.
//
// Example usage:
//
//	count := provider.ProviderCount()
//	log.Printf("Currently managing JWKS for %d issuers", count)
func (p *MultiIssuerProvider) ProviderCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.providers) + len(p.staticKeys)
}

// IssuerType represents the type of key management for an issuer.
type IssuerType string

const (
	// IssuerTypeOIDC indicates the issuer uses OIDC discovery for JWKS.
	IssuerTypeOIDC IssuerType = "oidc"
	// IssuerTypeSymmetric indicates the issuer uses a pre-shared symmetric key.
	IssuerTypeSymmetric IssuerType = "symmetric"
)

// IssuerInfo contains observability information about a single managed issuer.
type IssuerInfo struct {
	// Issuer is the issuer URL.
	Issuer string

	// Type indicates whether this issuer uses OIDC discovery or a symmetric key.
	Type IssuerType

	// Algorithm is the configured algorithm (only set for symmetric issuers).
	Algorithm string

	// LastUsed is the last time this issuer's provider was accessed (only set for OIDC issuers).
	LastUsed time.Time
}

// ProviderStats contains summary and per-issuer information about the
// MultiIssuerProvider's current state. Useful for monitoring dashboards
// and debugging authentication failures.
type ProviderStats struct {
	// Total is the total number of managed issuers (OIDC + symmetric).
	Total int

	// OIDC is the number of dynamically created OIDC providers.
	OIDC int

	// Symmetric is the number of statically configured symmetric issuers.
	Symmetric int

	// Issuers contains per-issuer detail.
	Issuers []IssuerInfo
}

// Stats returns observability information about all managed issuers.
// This includes both OIDC providers (dynamically cached) and symmetric
// issuers (statically configured via WithIssuerKeyConfig).
//
// Example:
//
//	stats := provider.Stats()
//	log.Printf("Managing %d issuers (%d OIDC, %d symmetric)", stats.Total, stats.OIDC, stats.Symmetric)
//	for _, info := range stats.Issuers {
//	    log.Printf("  %s: type=%s alg=%s lastUsed=%v", info.Issuer, info.Type, info.Algorithm, info.LastUsed)
//	}
func (p *MultiIssuerProvider) Stats() ProviderStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := ProviderStats{
		OIDC:      len(p.providers),
		Symmetric: len(p.staticKeys),
	}
	stats.Total = stats.OIDC + stats.Symmetric

	stats.Issuers = make([]IssuerInfo, 0, stats.Total)

	// Add OIDC providers
	for issuer, entry := range p.providers {
		stats.Issuers = append(stats.Issuers, IssuerInfo{
			Issuer:   issuer,
			Type:     IssuerTypeOIDC,
			LastUsed: entry.lastUsed,
		})
	}

	// Add symmetric issuers
	for issuer := range p.staticKeys {
		info := IssuerInfo{
			Issuer: issuer,
			Type:   IssuerTypeSymmetric,
		}
		if config, ok := p.issuerKeyConfigs[issuer]; ok {
			info.Algorithm = string(config.Algorithm)
		}
		stats.Issuers = append(stats.Issuers, info)
	}

	return stats
}

// buildSymmetricKeySet creates a jwk.Set containing a symmetric key with the
// specified algorithm and optional key ID. This allows symmetric keys to be
// handled through the same jwk.Set code path as asymmetric JWKS keys.
func buildSymmetricKeySet(secret []byte, alg validator.SignatureAlgorithm, keyID string) (jwk.Set, error) {
	key, err := jwk.Import(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to import symmetric key: %w", err)
	}

	jwxAlg, err := algToJWX(alg)
	if err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwxAlg); err != nil {
		return nil, fmt.Errorf("failed to set algorithm on key: %w", err)
	}

	if keyID != "" {
		if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
			return nil, fmt.Errorf("failed to set key ID: %w", err)
		}
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, fmt.Errorf("failed to add key to set: %w", err)
	}
	return set, nil
}

// algToJWX maps validator.SignatureAlgorithm to jwa.SignatureAlgorithm for
// symmetric algorithms. This is a local helper to avoid importing the
// validator's unexported stringToJWXAlgorithm function.
func algToJWX(alg validator.SignatureAlgorithm) (jwa.SignatureAlgorithm, error) {
	switch alg {
	case validator.HS256:
		return jwa.HS256(), nil
	case validator.HS384:
		return jwa.HS384(), nil
	case validator.HS512:
		return jwa.HS512(), nil
	default:
		var zero jwa.SignatureAlgorithm
		return zero, fmt.Errorf("unsupported symmetric algorithm: %s", alg)
	}
}
