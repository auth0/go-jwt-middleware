package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/jwks"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RedisCache implements the jwks.Cache interface using Redis as the backing store.
// This is useful for multi-tenant applications with 100+ issuers to avoid memory issues
// with the default in-memory cache.
type RedisCache struct {
	client     *redis.Client
	ttl        time.Duration
	httpClient *http.Client
}

// NewRedisCache creates a new Redis-backed cache for JWKS.
func NewRedisCache(redisAddr string, ttl time.Duration, httpClient *http.Client) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &RedisCache{
		client:     client,
		ttl:        ttl,
		httpClient: httpClient,
	}, nil
}

// Get retrieves JWKS from Redis or fetches it if not cached.
func (c *RedisCache) Get(ctx context.Context, jwksURI string) (jwks.KeySet, error) {
	// Try to get from Redis first
	cached, err := c.client.Get(ctx, jwksURI).Result()
	if err == nil {
		// Cache hit - parse the cached JWKS
		set, err := jwk.Parse([]byte(cached))
		if err != nil {
			log.Printf("Failed to parse cached JWKS from Redis: %v", err)
			// Fall through to fetch fresh JWKS
		} else {
			return set, nil
		}
	} else if err != redis.Nil {
		// Redis error (not a cache miss)
		log.Printf("Redis error: %v", err)
		// Fall through to fetch from network
	}

	// Cache miss or error - fetch from network
	set, err := jwk.Fetch(ctx, jwksURI, jwk.WithHTTPClient(c.httpClient))
	if err != nil {
		return nil, fmt.Errorf("could not fetch JWKS: %w", err)
	}

	// Serialize and cache in Redis
	jsonData, err := json.Marshal(set)
	if err != nil {
		log.Printf("Failed to marshal JWKS for caching: %v", err)
		// Return the set anyway, just don't cache it
		return set, nil
	}

	// Store in Redis with TTL (fire and forget - don't block on cache write)
	go func() {
		cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.client.Set(cacheCtx, jwksURI, jsonData, c.ttl).Err(); err != nil {
			log.Printf("Failed to cache JWKS in Redis: %v", err)
		}
	}()

	return set, nil
}

// Close closes the Redis connection.
func (c *RedisCache) Close() error {
	return c.client.Close()
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

	// Show which issuer validated the token
	response := map[string]any{
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

func setupHandler(issuers []string, audience []string, redisCache *RedisCache) http.Handler {
	// Use MultiIssuerProvider with Redis cache for large-scale multi-tenant applications
	// IMPORTANT: For 100+ tenants, using a custom cache like Redis is strongly recommended
	// to avoid memory issues with the default in-memory cache.
	//
	// Best practices:
	// - 10-100 issuers: Default settings (maxProviders=100) work well
	// - 100-1000 issuers: Use Redis + WithMaxProviders(500)
	// - 1000+ issuers: Use Redis + WithMaxProviders(1000)
	provider, err := jwks.NewMultiIssuerProvider(
		jwks.WithMultiIssuerCacheTTL(15*time.Minute),
		jwks.WithMultiIssuerCache(redisCache), // Use Redis cache for all issuers
		jwks.WithMaxProviders(1000),           // Limit in-memory providers for large scale
	)
	if err != nil {
		log.Fatalf("failed to create multi-issuer jwks provider: %v", err)
	}

	// Set up the validator with multiple issuers
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(provider.KeyFunc),
		validator.WithAlgorithm(validator.RS256),
		validator.WithIssuers(issuers), // Multiple issuers
		validator.WithAudiences(audience),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Set up the middleware using pure options pattern
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	return middleware.CheckJWT(handler)
}

func main() {
	// Create Redis cache for JWKS
	// IMPORTANT: This is recommended for applications with 100+ tenants/issuers
	redisCache, err := NewRedisCache("localhost:6379", 15*time.Minute, nil)
	if err != nil {
		log.Fatalf("failed to create Redis cache: %v", err)
	}
	defer redisCache.Close()

	// Configure multiple issuers - tokens from any of these issuers will be accepted
	// With Redis cache, this scales to hundreds or thousands of issuers
	issuers := []string{
		"https://tenant1.auth0.com/",
		"https://tenant2.auth0.com/",
		"https://tenant3.auth0.com/",
		// Add as many issuers as needed - Redis handles the memory management
	}

	mainHandler := setupHandler(issuers, []string{"<your api identifier>"}, redisCache)

	log.Println("Server listening on http://localhost:3000")
	log.Println("Using Redis cache for JWKS (recommended for 100+ tenants)")
	log.Printf("Accepting tokens from %d issuers", len(issuers))

	if err := http.ListenAndServe("0.0.0.0:3000", mainHandler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
