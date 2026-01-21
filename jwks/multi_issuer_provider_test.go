package jwks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v3/validator"
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
	t.Run("allows unlimited providers when maxProviders is 0", func(t *testing.T) {
		provider, err := NewMultiIssuerProvider(
			WithMaxProviders(0), // Unlimited
		)
		require.NoError(t, err)

		// Create multiple tenants
		servers := make([]*httptest.Server, 5)
		for i := range servers {
			servers[i] = createMockOIDCServer()
			defer servers[i].Close()
		}

		// Add all tenants - none should be evicted
		for _, server := range servers {
			ctx := validator.SetIssuerInContext(context.Background(), server.URL+"/")
			_, err := provider.KeyFunc(ctx)
			require.NoError(t, err)
		}

		// All 5 providers should still be cached
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
