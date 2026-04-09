package jwks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMultiIssuerProvider(t *testing.T) {
	t.Run("creates provider with default options", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider()

		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, 15*time.Minute, provider.cacheTTL)
		assert.NotNil(t, provider.httpClient)
		assert.NotNil(t, provider.providers)
		assert.Equal(t, 0, len(provider.providers))
		assert.Equal(t, 100, provider.maxProviders) // Default: 100 providers for MCD
	})

	t.Run("creates provider with custom TTL", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMultiIssuerCacheTTL(10 * time.Minute),
		)

		require.NoError(t, err)
		assert.Equal(t, 10*time.Minute, provider.cacheTTL)
	})

	t.Run("creates provider with custom HTTP client", func(t *testing.T) {
		customClient := &http.Client{Timeout: 5 * time.Second}
		provider, err := NewMultiIssuerProvider(
			WithMultiIssuerHTTPClient(customClient),
		)

		require.NoError(t, err)
		assert.Equal(t, customClient, provider.httpClient)
	})

	t.Run("returns error when HTTP client is nil", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMultiIssuerHTTPClient(nil),
		)

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "HTTP client cannot be nil")
	})

	t.Run("sets default TTL when zero is provided", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMultiIssuerCacheTTL(0),
		)

		require.NoError(t, err)
		assert.Equal(t, 15*time.Minute, provider.cacheTTL)
	})

	t.Run("returns error when negative TTL is provided", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMultiIssuerCacheTTL(-1 * time.Minute),
		)

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "cache TTL cannot be negative")
	})

	t.Run("creates provider with custom cache", func(t *testing.T) {
		customCache := &mockMultiIssuerCache{}
		provider, err := NewMultiIssuerProvider(
			WithMultiIssuerCache(customCache),
		)

		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, customCache, provider.cache)
	})

	t.Run("returns error when custom cache is nil", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMultiIssuerCache(nil),
		)

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "cache cannot be nil")
	})

	t.Run("creates provider with custom max providers", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMaxProviders(100),
		)

		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, 100, provider.maxProviders)
	})

	t.Run("returns error when max providers is negative", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMaxProviders(-1),
		)

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "max providers cannot be negative")
	})
}

func TestMultiIssuerProvider_KeyFunc(t *testing.T) {
	t.Run("returns error when issuer not in context", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		ctx := context.Background()
		key, err := provider.KeyFunc(ctx)

		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "issuer not found in context")
	})

	t.Run("returns error for invalid issuer URL", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		// Add issuer with invalid URL to context
		ctx := validator.SetIssuerInContext(context.Background(), "://invalid-url")

		key, err := provider.KeyFunc(ctx)

		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "invalid issuer URL")
	})

	t.Run("creates provider for new issuer on first request", func(t *testing.T) {
		// Create a mock OIDC server that returns JWKS
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				issuerURL := "http://" + r.Host + "/"
				fmt.Fprintf(w, `{"issuer":"%s","jwks_uri":"%s.well-known/jwks.json"}`, issuerURL, issuerURL)
			} else if r.URL.Path == "/.well-known/jwks.json" {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"keys":[]}`))
			}
		}))
		defer mockServer.Close()

		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		// Verify no providers exist initially
		assert.Equal(t, 0, provider.ProviderCount())

		// Add issuer to context
		ctx := validator.SetIssuerInContext(context.Background(), mockServer.URL+"/")

		// Call KeyFunc
		key, err := provider.KeyFunc(ctx)

		// Should succeed and create a provider
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 1, provider.ProviderCount())
	})

	t.Run("reuses existing provider for same issuer", func(t *testing.T) {
		// Create a mock OIDC server
		requestCount := 0
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				issuerURL := "http://" + r.Host + "/"
				fmt.Fprintf(w, `{"issuer":"%s","jwks_uri":"%s.well-known/jwks.json"}`, issuerURL, issuerURL)
			} else if r.URL.Path == "/.well-known/jwks.json" {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"keys":[]}`))
			}
		}))
		defer mockServer.Close()

		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		issuerURL := mockServer.URL + "/"
		ctx := validator.SetIssuerInContext(context.Background(), issuerURL)

		// First request - creates provider
		key1, err := provider.KeyFunc(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, key1)
		firstRequestCount := requestCount

		// Second request - reuses provider
		key2, err := provider.KeyFunc(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, key2)

		// Verify provider was reused (should use cache, minimal new requests)
		assert.Equal(t, 1, provider.ProviderCount())
		// The second request should not trigger discovery again (only JWKS fetch)
		assert.Less(t, requestCount-firstRequestCount, firstRequestCount)
	})

	t.Run("creates separate providers for different issuers", func(t *testing.T) {
		// Create mock servers for two different issuers
		mockServer1 := createMockOIDCServer()
		defer mockServer1.Close()

		mockServer2 := createMockOIDCServer()
		defer mockServer2.Close()

		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		// Request for issuer 1
		ctx1 := validator.SetIssuerInContext(context.Background(), mockServer1.URL+"/")
		key1, err := provider.KeyFunc(ctx1)
		assert.NoError(t, err)
		assert.NotNil(t, key1)

		// Request for issuer 2
		ctx2 := validator.SetIssuerInContext(context.Background(), mockServer2.URL+"/")
		key2, err := provider.KeyFunc(ctx2)
		assert.NoError(t, err)
		assert.NotNil(t, key2)

		// Should have created 2 separate providers
		assert.Equal(t, 2, provider.ProviderCount())
	})

	t.Run("uses custom cache when provided", func(t *testing.T) {
		// Create a mock OIDC server
		mockServer := createMockOIDCServer()
		defer mockServer.Close()

		// Create a mock cache that tracks Get calls
		mockCache := &mockMultiIssuerCache{
			GetCalls: make([]string, 0),
		}

		provider, err := NewMultiIssuerProvider(
			WithMultiIssuerCache(mockCache),
		)
		require.NoError(t, err)

		// Add issuer to context
		ctx := validator.SetIssuerInContext(context.Background(), mockServer.URL+"/")

		// Call KeyFunc
		key, err := provider.KeyFunc(ctx)

		// Should succeed and use the custom cache
		assert.NoError(t, err)
		assert.NotNil(t, key)

		// Verify the cache was called
		assert.Equal(t, 1, len(mockCache.GetCalls))
		assert.Contains(t, mockCache.GetCalls[0], "/.well-known/jwks.json")
	})
}

func TestMultiIssuerProvider_ProviderCount(t *testing.T) {
	t.Run("returns zero for new provider", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		assert.Equal(t, 0, provider.ProviderCount())
	})

	t.Run("returns correct count after creating providers", func(t *testing.T) {
		mockServer1 := createMockOIDCServer()
		defer mockServer1.Close()

		mockServer2 := createMockOIDCServer()
		defer mockServer2.Close()

		mockServer3 := createMockOIDCServer()
		defer mockServer3.Close()

		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		// Create providers for 3 issuers
		issuers := []string{
			mockServer1.URL + "/",
			mockServer2.URL + "/",
			mockServer3.URL + "/",
		}

		for _, issuer := range issuers {
			ctx := validator.SetIssuerInContext(context.Background(), issuer)
			_, err := provider.KeyFunc(ctx)
			require.NoError(t, err)
		}

		assert.Equal(t, 3, provider.ProviderCount())
	})
}

func TestMultiIssuerProvider_ConcurrentAccess(t *testing.T) {
	t.Run("handles concurrent requests for same issuer safely", func(t *testing.T) {
		mockServer := createMockOIDCServer()
		defer mockServer.Close()

		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		issuerURL := mockServer.URL + "/"
		ctx := validator.SetIssuerInContext(context.Background(), issuerURL)

		// Concurrent requests for the same issuer
		const concurrentRequests = 10
		errChan := make(chan error, concurrentRequests)

		for i := 0; i < concurrentRequests; i++ {
			go func() {
				_, err := provider.KeyFunc(ctx)
				errChan <- err
			}()
		}

		// Verify all requests succeeded
		for i := 0; i < concurrentRequests; i++ {
			err := <-errChan
			assert.NoError(t, err)
		}

		// Should only have created one provider (not 10)
		assert.Equal(t, 1, provider.ProviderCount())
	})

	t.Run("handles double-check locking correctly", func(t *testing.T) {
		mockServer := createMockOIDCServer()
		defer mockServer.Close()

		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		issuerURL := mockServer.URL + "/"
		ctx := validator.SetIssuerInContext(context.Background(), issuerURL)

		// Use a channel to synchronize goroutines to maximize chances of hitting double-check path
		startChan := make(chan struct{})
		errChan := make(chan error, 20)

		// Launch multiple goroutines that will all try to create provider simultaneously
		for i := 0; i < 20; i++ {
			go func() {
				<-startChan // Wait for signal
				_, err := provider.KeyFunc(ctx)
				errChan <- err
			}()
		}

		// Signal all goroutines to start at the same time
		close(startChan)

		// Collect all results
		for i := 0; i < 20; i++ {
			err := <-errChan
			assert.NoError(t, err)
		}

		// Should only have created one provider despite concurrent access
		assert.Equal(t, 1, provider.ProviderCount())
	})

	t.Run("handles concurrent requests for different issuers safely", func(t *testing.T) {
		// Create multiple mock servers
		servers := make([]*httptest.Server, 5)
		for i := range servers {
			servers[i] = createMockOIDCServer()
			defer servers[i].Close()
		}

		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		// Concurrent requests for different issuers
		errChan := make(chan error, len(servers))

		for _, server := range servers {
			go func(s *httptest.Server) {
				ctx := validator.SetIssuerInContext(context.Background(), s.URL+"/")
				_, err := provider.KeyFunc(ctx)
				errChan <- err
			}(server)
		}

		// Verify all requests succeeded
		for range servers {
			err := <-errChan
			assert.NoError(t, err)
		}

		// Should have created 5 separate providers
		assert.Equal(t, 5, provider.ProviderCount())
	})

	t.Run("returns error for invalid issuer URL", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider()
		if err != nil {
			t.Fatal(err)
		}

		// Set context with invalid issuer URL (contains invalid characters)
		ctx := validator.SetIssuerInContext(context.Background(), "ht!tp://invalid url with spaces/")

		// KeyFunc should fail to parse invalid issuer
		_, err = provider.KeyFunc(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer URL")
	})

	t.Run("returns error when issuer cannot be parsed as URL", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider()
		if err != nil {
			t.Fatal(err)
		}

		// Use a string that will fail URL parsing
		ctx := validator.SetIssuerInContext(context.Background(), "://missing-scheme")

		_, err = provider.KeyFunc(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer URL")
	})
}

// Helper function to create a mock OIDC server
func createMockOIDCServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			issuerURL := "http://" + r.Host + "/"
			fmt.Fprintf(w, `{"issuer":"%s","jwks_uri":"%s.well-known/jwks.json"}`, issuerURL, issuerURL)
		} else if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[]}`))
		} else {
			http.NotFound(w, r)
		}
	}))
}

// mockMultiIssuerCache is a mock implementation of the Cache interface for testing multi-issuer providers
type mockMultiIssuerCache struct {
	GetCalls []string
}

func (m *mockMultiIssuerCache) Get(ctx context.Context, jwksURI string) (KeySet, error) {
	m.GetCalls = append(m.GetCalls, jwksURI)
	// Return an empty JWKS set for testing
	return []byte(`{"keys":[]}`), nil
}

func TestMultiIssuerProvider_LRUEviction(t *testing.T) {
	t.Run("maxProviders 0 resets to default instead of unlimited", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMaxProviders(0), // Should reset to default (100)
		)
		require.NoError(t, err)
		assert.Equal(t, 100, provider.maxProviders)

		// Create multiple tenants - none should be evicted (well under ceiling)
		servers := make([]*httptest.Server, 5)
		for i := range servers {
			servers[i] = createMockOIDCServer()
			defer servers[i].Close()
		}

		for _, server := range servers {
			ctx := validator.SetIssuerInContext(context.Background(), server.URL+"/")
			_, err := provider.KeyFunc(ctx)
			require.NoError(t, err)
		}

		assert.Equal(t, 5, provider.ProviderCount())
	})

	t.Run("evicts least recently used provider when limit reached", func(t *testing.T) {
		// Create provider with max 2 providers
		provider, err := NewMultiIssuerProvider(
			WithMaxProviders(2),
		)
		require.NoError(t, err)

		tenant1 := createMockOIDCServer()
		defer tenant1.Close()

		tenant2 := createMockOIDCServer()
		defer tenant2.Close()

		tenant3 := createMockOIDCServer()
		defer tenant3.Close()

		// Add tenant1
		ctx1 := validator.SetIssuerInContext(context.Background(), tenant1.URL+"/")
		_, err = provider.KeyFunc(ctx1)
		require.NoError(t, err)
		assert.Equal(t, 1, provider.ProviderCount())

		// Add tenant2
		ctx2 := validator.SetIssuerInContext(context.Background(), tenant2.URL+"/")
		_, err = provider.KeyFunc(ctx2)
		require.NoError(t, err)
		assert.Equal(t, 2, provider.ProviderCount())

		// Add tenant3 - should evict tenant1 (LRU)
		ctx3 := validator.SetIssuerInContext(context.Background(), tenant3.URL+"/")
		_, err = provider.KeyFunc(ctx3)
		require.NoError(t, err)
		assert.Equal(t, 2, provider.ProviderCount())

		// Verify tenant1 is not in cache
		provider.mu.RLock()
		_, exists := provider.providers[tenant1.URL+"/"]
		provider.mu.RUnlock()
		assert.False(t, exists)

		// Verify tenant2 and tenant3 are in cache
		provider.mu.RLock()
		_, exists2 := provider.providers[tenant2.URL+"/"]
		_, exists3 := provider.providers[tenant3.URL+"/"]
		provider.mu.RUnlock()
		assert.True(t, exists2)
		assert.True(t, exists3)
	})

	t.Run("updates LRU order on access", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMaxProviders(2),
		)
		require.NoError(t, err)

		tenant1 := createMockOIDCServer()
		defer tenant1.Close()

		tenant2 := createMockOIDCServer()
		defer tenant2.Close()

		tenant3 := createMockOIDCServer()
		defer tenant3.Close()

		// Add tenant1 and tenant2
		ctx1 := validator.SetIssuerInContext(context.Background(), tenant1.URL+"/")
		_, err = provider.KeyFunc(ctx1)
		require.NoError(t, err)

		ctx2 := validator.SetIssuerInContext(context.Background(), tenant2.URL+"/")
		_, err = provider.KeyFunc(ctx2)
		require.NoError(t, err)

		// Access tenant1 again (move to front)
		_, err = provider.KeyFunc(ctx1)
		require.NoError(t, err)

		// Add tenant3 - should evict tenant2 (now LRU)
		ctx3 := validator.SetIssuerInContext(context.Background(), tenant3.URL+"/")
		_, err = provider.KeyFunc(ctx3)
		require.NoError(t, err)

		// Verify tenant2 was evicted, not tenant1
		provider.mu.RLock()
		_, exists1 := provider.providers[tenant1.URL+"/"]
		_, exists2 := provider.providers[tenant2.URL+"/"]
		_, exists3 := provider.providers[tenant3.URL+"/"]
		provider.mu.RUnlock()

		assert.True(t, exists1)
		assert.False(t, exists2)
		assert.True(t, exists3)
	})
}

// TestWithIssuerKeyConfig tests the symmetric issuer key configuration option.
func TestWithIssuerKeyConfig(t *testing.T) {
	t.Run("accepts valid symmetric config", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://symmetric.example.com/", IssuerKeyConfig{
				Secret:    []byte("my-secret-key"),
				Algorithm: validator.HS256,
			}),
		)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Contains(t, provider.staticKeys, "https://symmetric.example.com/")
	})

	t.Run("accepts config with key ID", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://symmetric.example.com/", IssuerKeyConfig{
				Secret:    []byte("my-secret-key"),
				Algorithm: validator.HS256,
				KeyID:     "my-key-id",
			}),
		)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("rejects empty issuer", func(t *testing.T) {
		_, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("", IssuerKeyConfig{
				Secret:    []byte("my-secret-key"),
				Algorithm: validator.HS256,
			}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer cannot be empty")
	})

	t.Run("rejects secret without algorithm", func(t *testing.T) {
		_, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://symmetric.example.com/", IssuerKeyConfig{
				Secret: []byte("my-secret-key"),
			}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm is required when secret is provided")
	})

	t.Run("rejects symmetric algorithm without secret", func(t *testing.T) {
		_, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://symmetric.example.com/", IssuerKeyConfig{
				Algorithm: validator.HS256,
			}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret is required for symmetric algorithm HS256")
	})

	t.Run("rejects asymmetric algorithm with secret", func(t *testing.T) {
		_, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://example.com/", IssuerKeyConfig{
				Secret:    []byte("my-secret-key"),
				Algorithm: validator.RS256,
			}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret cannot be used with asymmetric algorithm RS256")
		assert.Contains(t, err.Error(), "asymmetric issuers use OIDC discovery")
	})

	t.Run("rejects empty config", func(t *testing.T) {
		_, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://example.com/", IssuerKeyConfig{}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least secret and algorithm must be provided")
	})

	t.Run("supports multiple symmetric issuers", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://issuer1.example.com/", IssuerKeyConfig{
				Secret:    []byte("secret-1"),
				Algorithm: validator.HS256,
			}),
			WithIssuerKeyConfig("https://issuer2.example.com/", IssuerKeyConfig{
				Secret:    []byte("secret-2"),
				Algorithm: validator.HS384,
			}),
		)
		require.NoError(t, err)
		assert.Len(t, provider.staticKeys, 2)
	})
}

func TestWithIssuerKeyConfigs(t *testing.T) {
	t.Run("accepts batch configuration", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfigs(map[string]IssuerKeyConfig{
				"https://issuer1.example.com/": {Secret: []byte("secret-1"), Algorithm: validator.HS256},
				"https://issuer2.example.com/": {Secret: []byte("secret-2"), Algorithm: validator.HS384},
				"https://issuer3.example.com/": {Secret: []byte("secret-3"), Algorithm: validator.HS512},
			}),
		)
		require.NoError(t, err)
		assert.Len(t, provider.staticKeys, 3)
		assert.Contains(t, provider.staticKeys, "https://issuer1.example.com/")
		assert.Contains(t, provider.staticKeys, "https://issuer2.example.com/")
		assert.Contains(t, provider.staticKeys, "https://issuer3.example.com/")
	})

	t.Run("rejects empty configs map", func(t *testing.T) {
		_, err := NewMultiIssuerProvider(
			WithIssuerKeyConfigs(map[string]IssuerKeyConfig{}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer key configs cannot be empty")
	})

	t.Run("validates each entry", func(t *testing.T) {
		_, err := NewMultiIssuerProvider(
			WithIssuerKeyConfigs(map[string]IssuerKeyConfig{
				"https://valid.example.com/": {Secret: []byte("secret"), Algorithm: validator.HS256},
				"":                           {Secret: []byte("secret"), Algorithm: validator.HS256},
			}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer cannot be empty")
	})

	t.Run("can be combined with singular WithIssuerKeyConfig", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfigs(map[string]IssuerKeyConfig{
				"https://issuer1.example.com/": {Secret: []byte("secret-1"), Algorithm: validator.HS256},
				"https://issuer2.example.com/": {Secret: []byte("secret-2"), Algorithm: validator.HS256},
			}),
			WithIssuerKeyConfig("https://issuer3.example.com/", IssuerKeyConfig{
				Secret:    []byte("secret-3"),
				Algorithm: validator.HS384,
			}),
		)
		require.NoError(t, err)
		assert.Len(t, provider.staticKeys, 3)
	})
}

func TestMultiIssuerProvider_SymmetricKeyFunc(t *testing.T) {
	t.Run("returns static key set for symmetric issuer", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://symmetric.example.com/", IssuerKeyConfig{
				Secret:    []byte("my-secret-key"),
				Algorithm: validator.HS256,
			}),
		)
		require.NoError(t, err)

		ctx := validator.SetIssuerInContext(context.Background(), "https://symmetric.example.com/")
		key, err := provider.KeyFunc(ctx)

		assert.NoError(t, err)
		assert.NotNil(t, key)
		// 1 symmetric issuer, no OIDC providers
		assert.Equal(t, 1, provider.ProviderCount())
	})

	t.Run("falls through to OIDC discovery for non-symmetric issuer", func(t *testing.T) {
		mockServer := createMockOIDCServer()
		defer mockServer.Close()

		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://symmetric.example.com/", IssuerKeyConfig{
				Secret:    []byte("my-secret-key"),
				Algorithm: validator.HS256,
			}),
		)
		require.NoError(t, err)

		// Use OIDC issuer (not in staticKeys)
		ctx := validator.SetIssuerInContext(context.Background(), mockServer.URL+"/")
		key, err := provider.KeyFunc(ctx)

		assert.NoError(t, err)
		assert.NotNil(t, key)
		// 1 OIDC provider + 1 symmetric issuer
		assert.Equal(t, 2, provider.ProviderCount())
	})

	t.Run("mixed mode: symmetric + asymmetric issuers", func(t *testing.T) {
		mockServer := createMockOIDCServer()
		defer mockServer.Close()

		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://symmetric.example.com/", IssuerKeyConfig{
				Secret:    []byte("my-secret-key"),
				Algorithm: validator.HS256,
			}),
		)
		require.NoError(t, err)

		// Request for symmetric issuer
		ctx1 := validator.SetIssuerInContext(context.Background(), "https://symmetric.example.com/")
		key1, err := provider.KeyFunc(ctx1)
		assert.NoError(t, err)
		assert.NotNil(t, key1)

		// Request for asymmetric issuer (OIDC discovery)
		ctx2 := validator.SetIssuerInContext(context.Background(), mockServer.URL+"/")
		key2, err := provider.KeyFunc(ctx2)
		assert.NoError(t, err)
		assert.NotNil(t, key2)

		// 1 OIDC provider + 1 symmetric issuer
		assert.Equal(t, 2, provider.ProviderCount())
	})
}

// TestEvictLRUEdgeCases tests edge cases in LRU eviction
func TestEvictLRUEdgeCases(t *testing.T) {
	t.Run("handles eviction when LRU list is empty", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMaxProviders(1),
		)
		require.NoError(t, err)

		// Call evictLRU when list is empty (should not panic)
		provider.mu.Lock()
		provider.evictLRU()
		provider.mu.Unlock()

		// Should still work normally
		assert.Equal(t, 0, provider.ProviderCount())
	})
}

func TestMultiIssuerProvider_Stats(t *testing.T) {
	t.Run("empty provider", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider()
		require.NoError(t, err)

		stats := provider.Stats()
		assert.Equal(t, 0, stats.Total)
		assert.Equal(t, 0, stats.OIDC)
		assert.Equal(t, 0, stats.Symmetric)
		assert.Empty(t, stats.Issuers)
	})

	t.Run("symmetric issuers only", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfigs(map[string]IssuerKeyConfig{
				"https://hs256.example.com/": {Secret: []byte("secret-a"), Algorithm: validator.HS256},
				"https://hs384.example.com/": {Secret: []byte("secret-b"), Algorithm: validator.HS384},
			}),
		)
		require.NoError(t, err)

		stats := provider.Stats()
		assert.Equal(t, 2, stats.Total)
		assert.Equal(t, 0, stats.OIDC)
		assert.Equal(t, 2, stats.Symmetric)
		assert.Len(t, stats.Issuers, 2)

		// Verify per-issuer info
		byIssuer := make(map[string]IssuerInfo)
		for _, info := range stats.Issuers {
			byIssuer[info.Issuer] = info
		}

		hs256Info := byIssuer["https://hs256.example.com/"]
		assert.Equal(t, IssuerTypeSymmetric, hs256Info.Type)
		assert.Equal(t, "HS256", hs256Info.Algorithm)
		assert.True(t, hs256Info.LastUsed.IsZero())

		hs384Info := byIssuer["https://hs384.example.com/"]
		assert.Equal(t, IssuerTypeSymmetric, hs384Info.Type)
		assert.Equal(t, "HS384", hs384Info.Algorithm)
	})

	t.Run("mixed symmetric and OIDC", func(t *testing.T) {
		mockServer := createMockOIDCServer()
		defer mockServer.Close()

		provider, err := NewMultiIssuerProvider(
			WithIssuerKeyConfig("https://symmetric.example.com/", IssuerKeyConfig{
				Secret:    []byte("my-secret"),
				Algorithm: validator.HS256,
			}),
		)
		require.NoError(t, err)

		// Trigger OIDC provider creation
		ctx := validator.SetIssuerInContext(context.Background(), mockServer.URL+"/")
		_, err = provider.KeyFunc(ctx)
		require.NoError(t, err)

		stats := provider.Stats()
		assert.Equal(t, 2, stats.Total)
		assert.Equal(t, 1, stats.OIDC)
		assert.Equal(t, 1, stats.Symmetric)
		assert.Len(t, stats.Issuers, 2)

		// Verify per-issuer detail
		byIssuer := make(map[string]IssuerInfo)
		for _, info := range stats.Issuers {
			byIssuer[info.Issuer] = info
		}

		symInfo := byIssuer["https://symmetric.example.com/"]
		assert.Equal(t, IssuerTypeSymmetric, symInfo.Type)
		assert.Equal(t, "HS256", symInfo.Algorithm)

		oidcInfo := byIssuer[mockServer.URL+"/"]
		assert.Equal(t, IssuerTypeOIDC, oidcInfo.Type)
		assert.Empty(t, oidcInfo.Algorithm)
		assert.False(t, oidcInfo.LastUsed.IsZero())
	})
}

func TestAlgToJWX(t *testing.T) {
	t.Run("maps HS256", func(t *testing.T) {
		alg, err := algToJWX(validator.HS256)
		assert.NoError(t, err)
		assert.Equal(t, "HS256", alg.String())
	})

	t.Run("maps HS384", func(t *testing.T) {
		alg, err := algToJWX(validator.HS384)
		assert.NoError(t, err)
		assert.Equal(t, "HS384", alg.String())
	})

	t.Run("maps HS512", func(t *testing.T) {
		alg, err := algToJWX(validator.HS512)
		assert.NoError(t, err)
		assert.Equal(t, "HS512", alg.String())
	})

	t.Run("rejects unsupported algorithm", func(t *testing.T) {
		_, err := algToJWX(validator.RS256)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported symmetric algorithm")
	})
}

func TestBuildSymmetricKeySet(t *testing.T) {
	t.Run("builds HS256 key set", func(t *testing.T) {
		set, err := buildSymmetricKeySet([]byte("my-secret-key-32-bytes-long!!!!"), validator.HS256, "")
		assert.NoError(t, err)
		assert.Equal(t, 1, set.Len())
	})

	t.Run("builds HS384 key set", func(t *testing.T) {
		set, err := buildSymmetricKeySet([]byte("my-secret-key-32-bytes-long!!!!"), validator.HS384, "")
		assert.NoError(t, err)
		assert.Equal(t, 1, set.Len())
	})

	t.Run("builds HS512 key set", func(t *testing.T) {
		set, err := buildSymmetricKeySet([]byte("my-secret-key-32-bytes-long!!!!"), validator.HS512, "")
		assert.NoError(t, err)
		assert.Equal(t, 1, set.Len())
	})

	t.Run("builds key set with key ID", func(t *testing.T) {
		set, err := buildSymmetricKeySet([]byte("my-secret-key-32-bytes-long!!!!"), validator.HS256, "my-kid")
		assert.NoError(t, err)
		assert.Equal(t, 1, set.Len())

		key, ok := set.Key(0)
		assert.True(t, ok)
		kid, ok := key.KeyID()
		assert.True(t, ok)
		assert.Equal(t, "my-kid", kid)
	})

	t.Run("rejects unsupported algorithm", func(t *testing.T) {
		_, err := buildSymmetricKeySet([]byte("secret"), validator.RS256, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported symmetric algorithm")
	})
}

func TestMultiIssuerProvider_KeyFunc_NoIssuerInContext(t *testing.T) {
	provider, err := NewMultiIssuerProvider()
	require.NoError(t, err)

	// Call KeyFunc without issuer in context
	_, err = provider.KeyFunc(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer not found in context")
}
