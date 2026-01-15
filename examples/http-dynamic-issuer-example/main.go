package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

// tenantContextKey is the key for storing tenant ID in request context
type tenantContextKey struct{}

// issuerCache provides simple in-memory caching for issuer resolution
type issuerCache struct {
	mu    sync.RWMutex
	cache map[string]cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	issuers   []string
	expiresAt time.Time
}

func newIssuerCache(ttl time.Duration) *issuerCache {
	return &issuerCache{
		cache: make(map[string]cacheEntry),
		ttl:   ttl,
	}
}

func (c *issuerCache) get(tenantID string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[tenantID]
	if !exists || time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.issuers, true
}

func (c *issuerCache) set(tenantID string, issuers []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[tenantID] = cacheEntry{
		issuers:   issuers,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Database mock - in production, this would query your actual database
var tenantDatabase = map[string][]string{
	"tenant1": {
		"https://tenant1.auth0.com/",
	},
	"tenant2": {
		"https://tenant2.auth0.com/",
	},
	"tenant3": {
		"https://tenant3-primary.auth0.com/",
		"https://tenant3-backup.auth0.com/", // Migration scenario: accepting from both domains
	},
}

// getTenantIssuersFromDB simulates a database query
// In production, replace this with actual database call
func getTenantIssuersFromDB(ctx context.Context, tenantID string) ([]string, error) {
	// Simulate database query latency
	time.Sleep(10 * time.Millisecond)

	issuers, exists := tenantDatabase[tenantID]
	if !exists {
		return nil, nil // Return empty list for unknown tenants
	}

	return issuers, nil
}

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Modern type-safe claims retrieval using generics
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	if err != nil {
		http.Error(w, "failed to get validated claims", http.StatusInternalServerError)
		return
	}

	if len(claims.RegisteredClaims.Subject) == 0 {
		http.Error(w, "subject in JWT claims was empty", http.StatusBadRequest)
		return
	}

	// Get tenant ID from context (set by tenantMiddleware)
	tenantID, _ := r.Context().Value(tenantContextKey{}).(string)

	response := map[string]any{
		"tenant":  tenantID,
		"issuer":  claims.RegisteredClaims.Issuer,
		"subject": claims.RegisteredClaims.Subject,
		"claims":  claims,
	}

	payload, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

// tenantMiddleware extracts tenant ID from request headers
// In production, this might extract from subdomain, path, or custom header
func tenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract tenant from X-Tenant-ID header
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			http.Error(w, "X-Tenant-ID header is required", http.StatusBadRequest)
			return
		}

		// Add tenant to request context
		ctx := context.WithValue(r.Context(), tenantContextKey{}, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func setupHandler(audience []string) http.Handler {
	// Initialize issuer cache with 5 minute TTL
	cache := newIssuerCache(5 * time.Minute)

	// Use MultiIssuerProvider for automatic JWKS routing
	provider, err := jwks.NewMultiIssuerProvider(
		jwks.WithMultiIssuerCacheTTL(5*time.Minute),
	)
	if err != nil {
		log.Fatalf("failed to create multi-issuer jwks provider: %v", err)
	}

	// Dynamic issuer resolver with caching
	issuerResolver := func(ctx context.Context) ([]string, error) {
		// Extract tenant ID from context
		tenantID, ok := ctx.Value(tenantContextKey{}).(string)
		if !ok {
			return nil, nil // No tenant in context
		}

		// Check cache first (fast path)
		if cachedIssuers, found := cache.get(tenantID); found {
			log.Printf("[Cache HIT] Tenant %s: %v", tenantID, cachedIssuers)
			return cachedIssuers, nil
		}

		// Cache miss - query database (slow path)
		log.Printf("[Cache MISS] Querying database for tenant %s", tenantID)
		issuers, err := getTenantIssuersFromDB(ctx, tenantID)
		if err != nil {
			return nil, err
		}

		// Cache the result for next request
		if len(issuers) > 0 {
			cache.set(tenantID, issuers)
			log.Printf("[Database] Tenant %s: %v (cached for 5m)", tenantID, issuers)
		} else {
			log.Printf("[Database] Tenant %s: no issuers configured", tenantID)
		}

		return issuers, nil
	}

	// Set up the validator with dynamic issuer resolution
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuersResolver(issuerResolver), // Dynamic resolution
		validator.WithAudiences(audience),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Set up the middleware
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	// Chain middlewares: tenant extraction -> JWT validation -> handler
	return tenantMiddleware(middleware.CheckJWT(handler))
}

func main() {
	mainHandler := setupHandler([]string{"<your api identifier>"})

	log.Println("Server listening on http://localhost:3000")
	log.Println("Dynamic issuer resolution enabled with in-memory caching")
	log.Println("")
	log.Println("Configured tenants:")
	for tenantID, issuers := range tenantDatabase {
		log.Printf("  %s: %v", tenantID, issuers)
	}
	log.Println("")
	log.Println("Test with: curl -H 'X-Tenant-ID: tenant1' -H 'Authorization: Bearer YOUR_JWT' http://localhost:3000")

	if err := http.ListenAndServe("0.0.0.0:3000", mainHandler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
