package jwks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v2/internal/oidc"
)

func Test_JWKSProvider(t *testing.T) {
	var requestCount int32

	// Generate test JWKS
	expectedJWKS, err := generateJWKS()
	require.NoError(t, err)

	expectedCustomJWKS, err := generateJWKS()
	require.NoError(t, err)

	testServer := setupTestServer(t, expectedJWKS, expectedCustomJWKS, &requestCount)
	defer testServer.Close()

	testServerURL, err := url.Parse(testServer.URL)
	require.NoError(t, err)

	// Original provider tests
	t.Run("It correctly fetches the JWKS after calling the discovery endpoint", func(t *testing.T) {
		atomic.StoreInt32(&requestCount, 0)
		provider := NewProvider(testServerURL)
		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		jwkSet, ok := actualJWKS.(jwk.Set)
		require.True(t, ok)
		require.Greater(t, jwkSet.Len(), 0)

		// Should have made 2 requests: well-known + jwks
		assert.Equal(t, int32(2), atomic.LoadInt32(&requestCount))

		// Second call should reuse the jwksURI but still fetch JWKS
		atomic.StoreInt32(&requestCount, 0)
		secondJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount), "Second call should skip discovery")

		// Both results should be valid
		require.NotNil(t, secondJWKS)
		jwkSet2, ok := secondJWKS.(jwk.Set)
		require.True(t, ok)
		require.Greater(t, jwkSet2.Len(), 0)
	})

	t.Run("It skips the discovery if a custom JWKS_URI is provided", func(t *testing.T) {
		customJWKSURI, err := url.Parse(testServer.URL + "/custom/jwks.json")
		require.NoError(t, err)

		atomic.StoreInt32(&requestCount, 0)
		provider := NewProvider(testServerURL, WithCustomJWKSURI(customJWKSURI))
		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		jwkSet, ok := actualJWKS.(jwk.Set)
		require.True(t, ok)
		require.Greater(t, jwkSet.Len(), 0)

		// Should have made 1 request directly to custom URI
		assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))
	})

	t.Run("It uses the specified custom client", func(t *testing.T) {
		client := &http.Client{
			Timeout: time.Hour, // Unused value. We only need this to have a client different from the default.
		}
		provider := NewProvider(testServerURL, WithCustomClient(client))
		assert.Equal(t, client, provider.Client, "Expected custom client to be configured")
	})

	t.Run("It tells the provider to cancel fetching the JWKS if request is cancelled", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		provider := NewProvider(testServerURL)
		_, err := provider.KeyFunc(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context deadline exceeded")
	})

	t.Run("It fails to parse the jwks uri after fetching it from the discovery endpoint if malformed", func(t *testing.T) {
		malformedURL, err := url.Parse(testServer.URL + "/malformed")
		require.NoError(t, err)

		provider := NewProvider(malformedURL)
		_, err = provider.KeyFunc(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse \":\": missing protocol scheme")
	})

	t.Run("It fails when the well-known endpoint returns a malformed JWKS URI", func(t *testing.T) {
		malformedJWKSURL, err := url.Parse(testServer.URL + "/malformed_jwks_uri")
		require.NoError(t, err)

		provider := NewProvider(malformedJWKSURL)
		_, err = provider.KeyFunc(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse \"://malformed\": missing protocol scheme")
	})

	t.Run("It sets the caching TTL to 1 if 0 is provided when using the CachingProvider", func(t *testing.T) {
		provider := NewCachingProvider(testServerURL, 0)
		assert.Equal(t, time.Minute, provider.CacheTTL)
	})

	t.Run("It correctly applies both ProviderOptions and CachingProviderOptions when using the CachingProvider", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://example.com")
		jwksURL, _ := url.Parse("https://example.com/jwks")
		customClient := &http.Client{Timeout: 10 * time.Second}

		provider := NewCachingProvider(
			issuerURL,
			30*time.Second,
			WithCustomJWKSURI(jwksURL),
			WithCustomClient(customClient),
		)

		assert.Equal(t, jwksURL, provider.CustomJWKSURI, "CustomJWKSURI should be set correctly")
		assert.Equal(t, customClient, provider.Client, "Custom HTTP client should be set correctly")
	})

	t.Run("It panics when an invalid option type is provided when using the CachingProvider", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://example.com")

		assert.Panics(t, func() {
			NewCachingProvider(
				issuerURL,
				30*time.Second,
				"invalid_option",
			)
		}, "Expected panic when passing an invalid option type")
	})

	t.Run("CachingProvider handles errors from discovery endpoint", func(t *testing.T) {
		// Create a simple failing server
		errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Deliberate Test Error", http.StatusInternalServerError)
		}))
		defer errorServer.Close()

		// Create a properly formed URL
		errorURL, err := url.Parse(errorServer.URL)
		require.NoError(t, err)

		// Initialize provider
		provider := NewCachingProvider(errorURL, 5*time.Minute)

		// Make the call - this should fail
		_, err = provider.KeyFunc(context.Background())
		assert.Error(t, err)
		// Assert that we get an error and it contains the expected message
		if assert.Error(t, err, "Expected an error from discovery endpoint") {
			assert.Contains(t, err.Error(), "failed to retrieve well-known endpoints")
		}
	})

	t.Run("CachingProvider skips discovery with custom JWKS URI", func(t *testing.T) {
		customJWKSURI, err := url.Parse(testServer.URL + "/custom/jwks.json")
		require.NoError(t, err)

		atomic.StoreInt32(&requestCount, 0)
		provider := NewCachingProvider(testServerURL, 5*time.Minute, WithCustomJWKSURI(customJWKSURI))

		// First call should initialize cache with custom URI
		result, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		require.NotNil(t, result)

		// Should have made 1 request directly to custom URI
		assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))

		// Second call should use cache
		atomic.StoreInt32(&requestCount, 0)
		result2, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		require.NotNil(t, result2)

		// Should not have made any additional requests
		assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount))
	})

	t.Run("CachingProvider caches JWKS properly", func(t *testing.T) {
		atomic.StoreInt32(&requestCount, 0)
		provider := NewCachingProvider(testServerURL, 5*time.Minute)

		// First call should initialize and fetch
		result, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		require.NotNil(t, result)

		initialCount := atomic.LoadInt32(&requestCount)
		require.Greater(t, initialCount, int32(0), "Should have made initial requests")

		// Second call should use cache
		atomic.StoreInt32(&requestCount, 0)
		result2, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		require.NotNil(t, result2)

		// Should not have made any additional requests for cached result
		assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount))
	})

	t.Run("Concurrent access to CachingProvider.KeyFunc is safe", func(t *testing.T) {
		atomic.StoreInt32(&requestCount, 0)
		provider := NewCachingProvider(testServerURL, 5*time.Minute)

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := provider.KeyFunc(context.Background())
				assert.NoError(t, err)
			}()
		}
		wg.Wait()

		// Should not have made more than 2 requests (one for discovery, one for JWKS)
		assert.LessOrEqual(t, atomic.LoadInt32(&requestCount), int32(2),
			"Expected at most 2 requests regardless of concurrency")
	})

	t.Run("CachingProvider with custom JWKS URI caches correctly", func(t *testing.T) {
		atomic.StoreInt32(&requestCount, 0)
		customJWKSURI, err := url.Parse(testServer.URL + "/custom/jwks.json")
		require.NoError(t, err)

		provider := NewCachingProvider(testServerURL, 5*time.Minute, WithCustomJWKSURI(customJWKSURI))

		// First call should initialize cache and fetch from custom URI
		result1, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		initialCount := atomic.LoadInt32(&requestCount)
		assert.Equal(t, int32(1), initialCount, "Should make exactly one request to custom URI")

		// Second call should use cache
		atomic.StoreInt32(&requestCount, 0)
		result2, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount), "Should use cache for second call")

		// Both results should be valid
		for i, result := range []interface{}{result1, result2} {
			jwkSet, ok := result.(jwk.Set)
			require.True(t, ok, "Result %d should be a jwk.Set", i+1)
			assert.Greater(t, jwkSet.Len(), 0, "Result %d should have keys", i+1)
		}
	})

	t.Run("CachingProvider handles cache misses gracefully", func(t *testing.T) {
		atomic.StoreInt32(&requestCount, 0)
		provider := NewCachingProvider(testServerURL, 5*time.Minute)

		// First call should trigger cache initialization
		result1, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		require.NotNil(t, result1)

		// For our test, create a new provider with a different URL instead of modifying the existing one
		// This is a more realistic test scenario anyway
		customJWKSURI, err := url.Parse(testServer.URL + "/custom/jwks.json")
		require.NoError(t, err)

		// Create a new provider with the custom URI
		newProvider := NewCachingProvider(testServerURL, 5*time.Minute, WithCustomJWKSURI(customJWKSURI))

		// Reset counter
		atomic.StoreInt32(&requestCount, 0)

		// This should initialize the cache for the new custom URI
		result2, err := newProvider.KeyFunc(context.Background())
		require.NoError(t, err)
		require.NotNil(t, result2)

		// Should have made a request to fetch the custom JWKS
		assert.Greater(t, atomic.LoadInt32(&requestCount), int32(0), "Should make requests for new provider")

		// Reset counter again
		atomic.StoreInt32(&requestCount, 0)

		// Second call to new provider should use cache
		result3, err := newProvider.KeyFunc(context.Background())
		require.NoError(t, err)
		require.NotNil(t, result3)

		// Should not have made additional requests
		assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount), "Second call should use cache")

		// All results should be valid
		for i, result := range []interface{}{result1, result2, result3} {
			jwkSet, ok := result.(jwk.Set)
			require.True(t, ok, "Result %d should be a jwk.Set", i+1)
			assert.Greater(t, jwkSet.Len(), 0, "Result %d should have keys", i+1)
		}
	})

	t.Run("CachingProvider persists cache across multiple calls", func(t *testing.T) {
		atomic.StoreInt32(&requestCount, 0)
		provider := NewCachingProvider(testServerURL, 5*time.Minute)

		// Make initial request to initialize cache
		_, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		// Reset counter
		atomic.StoreInt32(&requestCount, 0)

		// Make several consecutive calls
		for i := 0; i < 10; i++ {
			result, err := provider.KeyFunc(context.Background())
			require.NoError(t, err)
			require.NotNil(t, result)
		}

		// Should not have made any additional requests
		assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount),
			"Cache should persist across multiple calls")
	})

	t.Run("It handles nil IssuerURL in Provider", func(t *testing.T) {
		var nilURL *url.URL
		provider := NewProvider(nilURL)

		// Attempting to use the provider should return an error
		_, err := provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer URL is required")
	})

	t.Run("It handles nil IssuerURL in CachingProvider", func(t *testing.T) {
		var nilURL *url.URL
		provider := NewCachingProvider(nilURL, 5*time.Minute)

		// Attempting to use the provider should return an error
		_, err := provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer URL is required")
	})

	t.Run("It handles empty JWKS URI from well-known endpoints", func(t *testing.T) {
		emptyJWKSURIServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				// Return empty JWKS URI
				wk := oidc.WellKnownEndpoints{JWKSURI: ""}
				err := json.NewEncoder(w).Encode(wk)
				require.NoError(t, err)
			}
		}))
		defer emptyJWKSURIServer.Close()

		serverURL, err := url.Parse(emptyJWKSURIServer.URL)
		require.NoError(t, err)

		provider := NewProvider(serverURL)
		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve well-known endpoints")
	})
	t.Run("CachingProvider handles empty JWKS URI from well-known endpoints", func(t *testing.T) {
		emptyJWKSURIServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				// Return empty JWKS URI
				wk := oidc.WellKnownEndpoints{JWKSURI: ""}
				err := json.NewEncoder(w).Encode(wk)
				require.NoError(t, err)
			}
		}))
		defer emptyJWKSURIServer.Close()

		serverURL, err := url.Parse(emptyJWKSURIServer.URL)
		require.NoError(t, err)

		provider := NewCachingProvider(serverURL, 5*time.Minute)
		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve well-known endpoints")
	})

	t.Run("CachingProvider handles expired cache with different jwks", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		firstJWKS, err := generateJWKS()
		require.NoError(t, err)
		firstKey, ok := firstJWKS.Key(0)
		require.True(t, ok)
		require.NoError(t, firstKey.Set(jwk.KeyIDKey, "first-key-id"))
		firstKeyID := "first-key-id"

		secondJWKS, err := generateJWKS()
		require.NoError(t, err)
		secondKey, ok := secondJWKS.Key(0)
		require.True(t, ok)
		require.NoError(t, secondKey.Set(jwk.KeyIDKey, "second-key-id"))
		secondKeyID := "second-key-id"

		cacheTTL := 3 * time.Second
		var currentJWKS jwk.Set = firstJWKS
		var serverCallCount int32
		var differentJWKSServer *httptest.Server
		differentJWKSServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&serverCallCount, 1)
			w.Header().Set("Cache-Control", "max-age=3")
			w.Header().Set("Expires", time.Now().Add(3*time.Second).Format(http.TimeFormat))
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				jwksURI := fmt.Sprintf("%s/different-jwks.json", differentJWKSServer.URL)
				require.NoError(t, json.NewEncoder(w).Encode(oidc.WellKnownEndpoints{JWKSURI: jwksURI}))
			} else if strings.Contains(r.URL.Path, "different-jwks.json") {
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(currentJWKS))
			}
		}))
		defer differentJWKSServer.Close()

		serverURL, err := url.Parse(differentJWKSServer.URL)
		require.NoError(t, err)

		provider := NewCachingProvider(serverURL, cacheTTL)

		// Initial fetch with first JWKS
		result1, err := provider.KeyFunc(ctx)
		require.NoError(t, err)
		jwkSet1, ok := result1.(jwk.Set)
		require.True(t, ok)
		firstResultKey, ok := jwkSet1.Key(0)
		require.True(t, ok)
		v, ok := firstResultKey.Get(jwk.KeyIDKey)
		require.True(t, ok)
		resultKeyID, ok := v.(string)
		require.True(t, ok)
		assert.Equal(t, firstKeyID, resultKeyID)

		// Update JWKS but fetch before cache expiry to confirm cached result is used
		currentJWKS = secondJWKS
		resultBeforeExpiry, err := provider.KeyFunc(ctx)
		require.NoError(t, err)
		jwkSetBeforeExpiry, ok := resultBeforeExpiry.(jwk.Set)
		require.True(t, ok)
		keyBeforeExpiry, ok := jwkSetBeforeExpiry.Key(0)
		require.True(t, ok)
		v, ok = keyBeforeExpiry.Get(jwk.KeyIDKey)
		require.True(t, ok)
		resultKeyID, ok = v.(string)
		require.True(t, ok)
		assert.Equal(t, firstKeyID, resultKeyID, "Should still return cached key before expiry")

		// Wait for cache expiration
		time.Sleep(cacheTTL + 2*time.Second)

		// Fetch after cache expiration to ensure it gets the updated JWKS
		result2, err := provider.KeyFunc(ctx)
		require.NoError(t, err)
		jwkSet2, ok := result2.(jwk.Set)
		require.True(t, ok)
		secondResultKey, ok := jwkSet2.Key(0)
		require.True(t, ok)
		v, ok = secondResultKey.Get(jwk.KeyIDKey)
		require.True(t, ok)
		resultKeyID, ok = v.(string)
		require.True(t, ok)
		assert.Equal(t, secondKeyID, resultKeyID)

		// Validate total server calls (1 for config, 1 for first JWKS, 1 for second JWKS)
		assert.Equal(t, int32(3), atomic.LoadInt32(&serverCallCount))
	})

	t.Run("It fails when discovery endpoint is unreachable", func(t *testing.T) {
		// Create a URL that points to a non-existent server
		unreachableURL, err := url.Parse("https://non-existent-server.example.com")
		require.NoError(t, err)

		provider := NewProvider(unreachableURL)
		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve well-known endpoints")
	})

	t.Run("It fails when JWKS endpoint returns non-200 status code", func(t *testing.T) {
		var jwksErrorServer *httptest.Server
		jwksErrorServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				jwksURI := fmt.Sprintf("%s/jwks-error", jwksErrorServer.URL)
				_ = json.NewEncoder(w).Encode(oidc.WellKnownEndpoints{JWKSURI: jwksURI})
			} else if strings.Contains(r.URL.Path, "jwks-error") {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}))
		defer jwksErrorServer.Close()

		jwksErrorURL, err := url.Parse(jwksErrorServer.URL)
		require.NoError(t, err)

		provider := NewProvider(jwksErrorURL)
		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal JWK set: invalid character")
	})

	t.Run("It fails when JWKS endpoint returns invalid JSON", func(t *testing.T) {
		// Create a server that returns invalid JSON for JWKS endpoint
		var invalidJSONServer *httptest.Server
		invalidJSONServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				jwksURI := fmt.Sprintf("%s/invalid-json", invalidJSONServer.URL)
				_ = json.NewEncoder(w).Encode(oidc.WellKnownEndpoints{JWKSURI: jwksURI})
			} else if strings.Contains(r.URL.Path, "invalid-json") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("this is not valid json"))
			}
		}))
		defer invalidJSONServer.Close()

		invalidJSONURL, err := url.Parse(invalidJSONServer.URL)
		require.NoError(t, err)

		provider := NewProvider(invalidJSONURL)
		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid character")
	})

	t.Run("It fails when JWKS endpoint returns empty JSON object", func(t *testing.T) {
		var emptyJSONServer *httptest.Server

		emptyJSONServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				jwksURI := fmt.Sprintf("%s/empty-json", emptyJSONServer.URL)
				_ = json.NewEncoder(w).Encode(oidc.WellKnownEndpoints{JWKSURI: jwksURI})
			} else if strings.Contains(r.URL.Path, "empty-json") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("{}"))
			}
		}))
		defer emptyJSONServer.Close()

		emptyJSONURL, err := url.Parse(emptyJSONServer.URL)
		require.NoError(t, err)

		provider := NewProvider(emptyJSONURL)
		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
	})

	t.Run("CachingProvider fails when discovery endpoint returns non-200 status code", func(t *testing.T) {
		badDiscoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}))
		defer badDiscoveryServer.Close()

		badDiscoveryURL, _ := url.Parse(badDiscoveryServer.URL)

		provider := NewCachingProvider(badDiscoveryURL, 5*time.Minute)
		_, err := provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve well-known endpoints")
	})

	t.Run("CachingProvider fails when discovery endpoint returns invalid JSON", func(t *testing.T) {
		invalidDiscoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("this is not valid json"))
		}))
		defer invalidDiscoveryServer.Close()

		invalidDiscoveryURL, _ := url.Parse(invalidDiscoveryServer.URL)

		provider := NewCachingProvider(invalidDiscoveryURL, 5*time.Minute)
		_, err := provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve well-known endpoints")
	})

	t.Run("CachingProvider handles cache refresh failures gracefully", func(t *testing.T) {
		ctx := context.Background()

		// Create a server that works for the first request but fails afterward
		attempt := 0
		var failingRefreshServer *httptest.Server

		failingRefreshServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				jwksURI := fmt.Sprintf("%s/failing-jwks", failingRefreshServer.URL)
				_ = json.NewEncoder(w).Encode(oidc.WellKnownEndpoints{JWKSURI: jwksURI})
			} else if strings.Contains(r.URL.Path, "failing-jwks") {
				attempt++
				if attempt == 1 {
					// First attempt succeeds
					w.Header().Set("Content-Type", "application/json")
					testJWKS, _ := generateJWKS()
					buf, _ := json.Marshal(testJWKS)
					_, _ = w.Write(buf)
				} else {
					// Subsequent attempts fail
					http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				}
			}
		}))
		defer failingRefreshServer.Close()

		failingRefreshURL, _ := url.Parse(failingRefreshServer.URL)

		// Use a very short cache TTL to force refresh attempts
		provider := NewCachingProvider(failingRefreshURL, 100*time.Millisecond)

		// First call should succeed
		result1, err := provider.KeyFunc(ctx)
		require.NoError(t, err)
		require.NotNil(t, result1)

		// Wait for cache to expire
		time.Sleep(200 * time.Millisecond)

		// Second call should still work (using cached value) even though refresh fails
		result2, err := provider.KeyFunc(ctx)
		require.NoError(t, err)
		require.NotNil(t, result2)

		// Both results should be valid
		for i, result := range []interface{}{result1, result2} {
			jwkSet, ok := result.(jwk.Set)
			require.True(t, ok, "Result %d should be a jwk.Set", i+1)
			assert.Greater(t, jwkSet.Len(), 0, "Result %d should have keys", i+1)
		}
	})

	t.Run("It fails when discovery returns non-JSON response", func(t *testing.T) {
		nonJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("This is not JSON"))
		}))
		defer nonJSONServer.Close()

		nonJSONURL, _ := url.Parse(nonJSONServer.URL)

		provider := NewProvider(nonJSONURL)
		_, err := provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve well-known endpoints")
	})

	t.Run("It handles HTTP redirects correctly", func(t *testing.T) {
		redirectCounter := 0
		var redirectServer *httptest.Server
		redirectServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				redirectCounter++
				http.Redirect(w, r, "/redirect-target/.well-known/openid-configuration", http.StatusFound)
			case "/redirect-target/.well-known/openid-configuration":
				jwksURI := fmt.Sprintf("%s/redirect-target/jwks.json", redirectServer.URL)
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(oidc.WellKnownEndpoints{JWKSURI: jwksURI})
				require.NoError(t, err, "Failed to encode well-known endpoints")
			case "/redirect-target/jwks.json":
				w.Header().Set("Content-Type", "application/json")
				testJWKS, _ := generateJWKS()
				buf, _ := json.Marshal(testJWKS)
				_, _ = w.Write(buf)
			default:
				http.NotFound(w, r)
			}
		}))
		defer redirectServer.Close()

		redirectURL, _ := url.Parse(redirectServer.URL)
		provider := NewProvider(redirectURL)

		result, err := provider.KeyFunc(context.Background())
		require.NoError(t, err, "Expected no error during key retrieval")
		require.NotNil(t, result, "Expected a non-nil result")

		assert.Greater(t, redirectCounter, 0, "Redirect should have been followed")
	})
}

func generateJWKS() (jwk.Set, error) {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a JWK from the public key
	key, err := jwk.FromRaw(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	// Set key ID
	if err := key.Set(jwk.KeyIDKey, "test-key-id"); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Create a new JWKS and add the key
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, fmt.Errorf("failed to add key to set: %w", err)
	}

	return set, nil
}

func setupTestServer(
	t *testing.T,
	expectedJWKS jwk.Set,
	expectedCustomJWKS jwk.Set,
	requestCount *int32,
) (server *httptest.Server) {
	t.Helper()

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(requestCount, 1)

		urlCheck := r.URL.Path
		t.Logf("Request to: %s", urlCheck)

		switch {
		case strings.HasSuffix(r.URL.Path, "/malformed/.well-known/openid-configuration"):
			wk := oidc.WellKnownEndpoints{JWKSURI: ":"}
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case strings.HasSuffix(r.URL.Path, "/malformed_jwks_uri/.well-known/openid-configuration"):
			wk := oidc.WellKnownEndpoints{JWKSURI: "://malformed"}
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			wk := oidc.WellKnownEndpoints{JWKSURI: server.URL + "/.well-known/jwks.json"}
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case strings.HasSuffix(r.URL.Path, "/.well-known/jwks.json"):
			w.Header().Set("Content-Type", "application/json")
			buf, err := json.Marshal(expectedJWKS)
			require.NoError(t, err)
			_, err = w.Write(buf)
			require.NoError(t, err)
		case strings.HasSuffix(r.URL.Path, "/custom/jwks.json"):
			w.Header().Set("Content-Type", "application/json")
			buf, err := json.Marshal(expectedCustomJWKS)
			require.NoError(t, err)
			_, err = w.Write(buf)
			require.NoError(t, err)
		case strings.Contains(r.URL.Path, "/error/.well-known/openid-configuration"):
			// Explicitly return error for the well-known endpoint
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		case strings.Contains(r.URL.Path, "/error"):
			// Any other error path
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		default:
			t.Logf("Unhandled path: %s", r.URL.Path)
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))

	return server
}
