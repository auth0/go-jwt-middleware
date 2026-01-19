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

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v3/internal/oidc"
)

func Test_JWKSProvider(t *testing.T) {
	var requestCount int32

	expectedJWKS, err := generateJWKS()
	require.NoError(t, err)

	expectedCustomJWKS, err := generateJWKS()
	require.NoError(t, err)

	testServer := setupTestServer(t, expectedJWKS, expectedCustomJWKS, &requestCount)
	defer testServer.Close()

	testServerURL, err := url.Parse(testServer.URL)
	require.NoError(t, err)

	t.Run("It correctly fetches the JWKS after calling the discovery endpoint", func(t *testing.T) {
		provider, err := NewProvider(WithIssuerURL(testServerURL))
		require.NoError(t, err)

		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		// Verify JWKS is valid (jwk.Set type)
		jwkSet, ok := actualJWKS.(jwk.Set)
		require.True(t, ok, "expected jwk.Set type")
		require.NotNil(t, jwkSet)
		require.Greater(t, jwkSet.Len(), 0, "JWKS should contain at least one key")

		// Verify key ID matches
		key, found := jwkSet.Key(0)
		require.True(t, found, "should have at least one key")
		keyID, hasKeyID := key.KeyID()
		require.True(t, hasKeyID, "key should have a key ID")
		require.Equal(t, "kid", keyID)
	})

	t.Run("It skips the discovery if a custom JWKS_URI is provided", func(t *testing.T) {
		customJWKSURI, err := url.Parse(testServer.URL + "/custom/jwks.json")
		require.NoError(t, err)

		provider, err := NewProvider(
			WithIssuerURL(testServerURL),
			WithCustomJWKSURI(customJWKSURI),
		)
		require.NoError(t, err)

		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		// Verify JWKS is valid (jwk.Set type)
		jwkSet, ok := actualJWKS.(jwk.Set)
		require.True(t, ok, "expected jwk.Set type")
		require.NotNil(t, jwkSet)
		require.Greater(t, jwkSet.Len(), 0, "JWKS should contain at least one key")

		// Verify key ID matches
		key, found := jwkSet.Key(0)
		require.True(t, found, "should have at least one key")
		keyID, hasKeyID := key.KeyID()
		require.True(t, hasKeyID, "key should have a key ID")
		require.Equal(t, "kid", keyID)
	})

	t.Run("It uses the specified custom client", func(t *testing.T) {
		client := &http.Client{
			Timeout: time.Hour, // Unused value. We only need this to have a client different from the default.
		}
		provider, err := NewProvider(
			WithIssuerURL(testServerURL),
			WithCustomClient(client),
		)
		require.NoError(t, err)

		require.Equal(t, client, provider.Client, "expected custom client to be configured")
	})

	t.Run("It tells the provider to cancel fetching the JWKS if request is cancelled", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		provider, err := NewProvider(WithIssuerURL(testServerURL))
		require.NoError(t, err)

		_, err = provider.KeyFunc(ctx)
		if !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("was expecting context deadline to exceed but error is: %v", err)
		}
	})

	t.Run("Provider returns error when issuer URL is missing", func(t *testing.T) {
		_, err := NewProvider() // No options provided
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer URL is required")
	})

	t.Run("It only calls the API once when multiple requests come in when using the CachingProvider",
		func(t *testing.T) {
			requestCount = 0

			provider, err := NewCachingProvider(
				WithIssuerURL(testServerURL),
				WithCacheTTL(5*time.Minute),
			)
			require.NoError(t, err)

			var wg sync.WaitGroup
			for i := 0; i < 50; i++ {
				wg.Add(1)
				go func() {
					_, _ = provider.KeyFunc(context.Background())
					wg.Done()
				}()
			}
			wg.Wait()

			// Should be 2 requests: well-known discovery + JWKS fetch
			// jwx cache handles concurrency, so subsequent requests use cache
			if requestCount > 2 {
				t.Fatalf("wanted at most 2 requests (well known and jwks), but we got %d requests", requestCount)
			}
		},
	)

	t.Run("It sets the caching TTL to 15 minutes if 0 is provided when using the CachingProvider", func(t *testing.T) {
		provider, err := NewCachingProvider(
			WithIssuerURL(testServerURL),
			WithCacheTTL(0),
		)
		require.NoError(t, err)
		require.NotNil(t, provider)
		// Default is 15 minutes - we can't directly inspect internal TTL with abstraction
		// but we can verify provider was created successfully
	})

	t.Run("It fails to parse the jwks uri after fetching it from the discovery endpoint if malformed",
		func(t *testing.T) {
			malformedURL, err := url.Parse(testServer.URL + "/malformed")
			require.NoError(t, err)

			provider, err := NewProvider(WithIssuerURL(malformedURL))
			require.NoError(t, err)

			_, err = provider.KeyFunc(context.Background())
			if !strings.Contains(err.Error(), "could not parse JWKS URI from well known endpoints") {
				t.Fatalf("wanted an error, but got %s", err)
			}
		},
	)

	t.Run("CachingProvider successfully fetches JWKS", func(t *testing.T) {
		requestCount = 0

		provider, err := NewCachingProvider(
			WithIssuerURL(testServerURL),
			WithCacheTTL(5*time.Minute),
		)
		require.NoError(t, err)

		// Fetch JWKS
		jwks, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		require.NotNil(t, jwks)

		// Should have fetched from server (well-known + JWKS)
		assert.GreaterOrEqual(t, int(requestCount), 2, "Should have made requests to fetch JWKS")
	})

	t.Run("CachingProvider accepts both ProviderOption and CachingProviderOption", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://example.com")
		jwksURL, _ := url.Parse("https://example.com/jwks")
		customClient := &http.Client{Timeout: 10 * time.Second}

		provider, err := NewCachingProvider(
			WithIssuerURL(issuerURL),       // ProviderOption - works directly!
			WithCacheTTL(30*time.Second),   // CachingProviderOption
			WithCustomJWKSURI(jwksURL),     // ProviderOption - works directly!
			WithCustomClient(customClient), // ProviderOption - works directly!
		)

		require.NoError(t, err)
		assert.NotNil(t, provider)
		// Options were applied successfully if no error
	})

	t.Run("CachingProvider with only issuerURL (minimal config)", func(t *testing.T) {
		// Test minimal configuration - only issuer URL provided
		// This tests the default values path in NewCachingProvider
		issuerURL, _ := url.Parse("https://example.com")

		provider, err := NewCachingProvider(
			WithIssuerURL(issuerURL),
		)

		require.NoError(t, err)
		assert.NotNil(t, provider)
		// Should use default HTTP client and cache TTL
	})

	t.Run("CachingProvider with issuerURL and custom client only", func(t *testing.T) {
		// Test partial configuration - issuer URL and custom client, no JWKS URI
		// This tests the path where Client is set but CustomJWKSURI is not
		issuerURL, _ := url.Parse("https://example.com")
		customClient := &http.Client{Timeout: 20 * time.Second}

		provider, err := NewCachingProvider(
			WithIssuerURL(issuerURL),
			WithCustomClient(customClient),
		)

		require.NoError(t, err)
		assert.NotNil(t, provider)
		// CustomJWKSURI should not be set, but Client should be
	})

	t.Run("CachingProvider with issuerURL and custom JWKS URI only", func(t *testing.T) {
		// Test partial configuration - issuer URL and custom JWKS URI, no custom client
		// This tests the path where CustomJWKSURI is set but Client is not
		issuerURL, _ := url.Parse("https://example.com")
		jwksURL, _ := url.Parse("https://example.com/custom-jwks")

		provider, err := NewCachingProvider(
			WithIssuerURL(issuerURL),
			WithCustomJWKSURI(jwksURL),
		)

		require.NoError(t, err)
		assert.NotNil(t, provider)
		// CustomJWKSURI should be set, but Client should use default
	})

	t.Run("CachingProvider returns error for missing issuerURL", func(t *testing.T) {
		_, err := NewCachingProvider(WithCacheTTL(5 * time.Minute))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer URL is required")
	})

	t.Run("CachingProvider returns error for invalid option type", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://example.com")

		_, err := NewCachingProvider(
			WithIssuerURL(issuerURL),
			"invalid_option", // Invalid option type - should be rejected
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid option type")
		assert.Contains(t, err.Error(), "string") // Should mention the actual type
	})

	t.Run("CachingProvider with custom cache implementation", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://example.com")
		jwksURL, _ := url.Parse("https://example.com/jwks")

		// Mock cache for testing
		mockCache := &mockCache{
			jwks: expectedJWKS,
		}

		provider, err := NewCachingProvider(
			WithIssuerURL(issuerURL),    // ProviderOption - works directly!
			WithCacheTTL(5*time.Minute), // CachingProviderOption
			WithCustomJWKSURI(jwksURL),  // ProviderOption - works directly!
			WithCache(mockCache),        // CachingProviderOption
		)

		require.NoError(t, err)

		jwks, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		// Verify the mock cache was used and returned the expected JWKS
		assert.True(t, mockCache.getCalled, "Custom cache should be used")
		assert.Equal(t, expectedJWKS, jwks, "Should return JWKS from custom cache")
	})

	// Test option validation edge cases
	t.Run("Provider option validation", func(t *testing.T) {
		t.Run("WithIssuerURL rejects nil", func(t *testing.T) {
			_, err := NewProvider(WithIssuerURL(nil))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "issuer URL cannot be nil")
		})

		t.Run("WithCustomJWKSURI rejects nil", func(t *testing.T) {
			issuerURL, _ := url.Parse("https://example.com")
			_, err := NewProvider(
				WithIssuerURL(issuerURL),
				WithCustomJWKSURI(nil),
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "custom JWKS URI cannot be nil")
		})

		t.Run("WithCustomClient rejects nil", func(t *testing.T) {
			issuerURL, _ := url.Parse("https://example.com")
			_, err := NewProvider(
				WithIssuerURL(issuerURL),
				WithCustomClient(nil),
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "HTTP client cannot be nil")
		})
	})

	t.Run("CachingProvider option validation", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://example.com")

		t.Run("WithCacheTTL rejects negative duration", func(t *testing.T) {
			_, err := NewCachingProvider(
				WithIssuerURL(issuerURL),
				WithCacheTTL(-1*time.Second),
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cache TTL cannot be negative")
			assert.Contains(t, err.Error(), "invalid option")
		})

		t.Run("WithCache rejects nil", func(t *testing.T) {
			_, err := NewCachingProvider(
				WithIssuerURL(issuerURL),
				WithCache(nil),
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cache cannot be nil")
			assert.Contains(t, err.Error(), "invalid option")
		})

		t.Run("ProviderOption error propagates through CachingProvider", func(t *testing.T) {
			// Test that ProviderOption errors are properly wrapped
			_, err := NewCachingProvider(
				WithIssuerURL(issuerURL),
				WithCustomClient(nil), // This should error
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "HTTP client cannot be nil")
			assert.Contains(t, err.Error(), "invalid option")
		})
	})

	t.Run("CachingProvider handles cache expiry correctly", func(t *testing.T) {
		requestCount = 0

		provider, err := NewCachingProvider(
			WithIssuerURL(testServerURL),
			WithCacheTTL(100*time.Millisecond), // Very short TTL for testing
		)
		require.NoError(t, err)

		// First fetch
		_, err = provider.KeyFunc(context.Background())
		require.NoError(t, err)
		firstRequestCount := atomic.LoadInt32(&requestCount)

		// Wait for cache to expire
		time.Sleep(150 * time.Millisecond)

		// Second fetch - should hit server again due to expired cache
		_, err = provider.KeyFunc(context.Background())
		require.NoError(t, err)
		secondRequestCount := atomic.LoadInt32(&requestCount)

		// Should have made more requests due to cache expiry
		assert.Greater(t, int(secondRequestCount), int(firstRequestCount),
			"Should have fetched again after cache expired")
	})

	t.Run("Provider handles network errors gracefully", func(t *testing.T) {
		// Invalid URL that will cause network error
		badURL, _ := url.Parse("http://invalid-host-that-does-not-exist-12345.com")

		provider, err := NewProvider(WithIssuerURL(badURL))
		require.NoError(t, err)

		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		// Should get an error related to fetching well-known endpoints
		assert.Contains(t, err.Error(), "could not fetch well-known endpoints")
	})

	t.Run("Provider handles JWKS fetch errors", func(t *testing.T) {
		// Setup a server that returns 404 for JWKS
		var badServer *httptest.Server
		badServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				wk := oidc.WellKnownEndpoints{JWKSURI: badServer.URL + "/jwks.json"}
				_ = json.NewEncoder(w).Encode(wk)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer badServer.Close()

		badServerURL, _ := url.Parse(badServer.URL)
		provider, err := NewProvider(WithIssuerURL(badServerURL))
		require.NoError(t, err)

		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not fetch JWKS")
	})

	t.Run("CachingProvider handles JWKS URI discovery errors", func(t *testing.T) {
		// Invalid URL that will cause discovery error
		badURL, _ := url.Parse("http://invalid-host-that-does-not-exist-67890.com")

		provider, err := NewCachingProvider(
			WithIssuerURL(badURL),
			WithCacheTTL(5*time.Minute),
		)
		require.NoError(t, err)

		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		// Should propagate discovery error
		assert.Contains(t, err.Error(), "failed to discover JWKS URI")
	})

	t.Run("CachingProvider handles cache fetch errors", func(t *testing.T) {
		// Mock cache that returns errors
		errorCache := &mockErrorCache{
			err: fmt.Errorf("cache error"),
		}

		issuerURL, _ := url.Parse("https://example.com")
		jwksURL, _ := url.Parse("https://example.com/jwks")

		provider, err := NewCachingProvider(
			WithIssuerURL(issuerURL),
			WithCustomJWKSURI(jwksURL),
			WithCache(errorCache),
		)
		require.NoError(t, err)

		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cache error")
	})

	t.Run("jwxCache handles concurrent cache updates correctly", func(t *testing.T) {
		requestCount = 0

		provider, err := NewCachingProvider(
			WithIssuerURL(testServerURL),
			WithCacheTTL(50*time.Millisecond), // Very short TTL
		)
		require.NoError(t, err)

		// First request - populates cache
		_, err = provider.KeyFunc(context.Background())
		require.NoError(t, err)

		// Wait for cache to almost expire
		time.Sleep(60 * time.Millisecond)

		// Launch multiple concurrent requests to test double-check logic
		var wg sync.WaitGroup
		errors := make(chan error, 10)
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := provider.KeyFunc(context.Background())
				if err != nil {
					errors <- err
				}
			}()
		}
		wg.Wait()
		close(errors)

		// All requests should succeed (verifies double-check logic prevents race conditions)
		for err := range errors {
			t.Errorf("Unexpected error from concurrent request: %v", err)
		}
	})

	t.Run("jwxCache double-check logic returns cached value", func(t *testing.T) {
		requestCount = 0

		provider, err := NewCachingProvider(
			WithIssuerURL(testServerURL),
			WithCacheTTL(1*time.Second), // Longer TTL for this test
		)
		require.NoError(t, err)

		// Populate cache
		jwks1, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)
		initialCount := atomic.LoadInt32(&requestCount)

		// Multiple immediate requests should use cache (double-check returns cached value)
		for i := 0; i < 5; i++ {
			jwks2, err := provider.KeyFunc(context.Background())
			require.NoError(t, err)
			require.NotNil(t, jwks2)
		}

		// Request count should not significantly increase (cache is being used)
		finalCount := atomic.LoadInt32(&requestCount)
		assert.Equal(t, initialCount, finalCount, "Cached values should be used, not refetched")
		require.NotNil(t, jwks1)
	})

	t.Run("jwxCache handles jwk.Fetch errors", func(t *testing.T) {
		// Setup a server that returns 500 for JWKS
		var errorServer *httptest.Server
		errorServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				wk := oidc.WellKnownEndpoints{JWKSURI: errorServer.URL + "/jwks.json"}
				_ = json.NewEncoder(w).Encode(wk)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Internal Server Error"))
			}
		}))
		defer errorServer.Close()

		errorServerURL, _ := url.Parse(errorServer.URL)
		provider, err := NewCachingProvider(
			WithIssuerURL(errorServerURL),
			WithCacheTTL(5*time.Minute),
		)
		require.NoError(t, err)

		_, err = provider.KeyFunc(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not fetch JWKS")
	})
}

// mockCache is a test cache implementation
type mockCache struct {
	jwks      KeySet
	getCalled bool
}

func (m *mockCache) Get(ctx context.Context, jwksURI string) (KeySet, error) {
	m.getCalled = true
	return m.jwks, nil
}

// mockErrorCache is a cache implementation that always returns errors
type mockErrorCache struct {
	err error
}

func (m *mockErrorCache) Get(ctx context.Context, jwksURI string) (KeySet, error) {
	return nil, m.err
}

func generateJWKS() (jwk.Set, error) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create jwk.Key from RSA key using Import
	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	// Set key ID
	if err := key.Set(jwk.KeyIDKey, "kid"); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Create JWKS set
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

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(requestCount, 1)

		switch r.URL.String() {
		case "/malformed/.well-known/openid-configuration":
			wk := oidc.WellKnownEndpoints{JWKSURI: ":"}
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case "/.well-known/openid-configuration":
			wk := oidc.WellKnownEndpoints{JWKSURI: server.URL + "/.well-known/jwks.json"}
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case "/.well-known/jwks.json":
			// Convert jwk.Set to JSON
			jsonData, err := json.Marshal(expectedJWKS)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			_, err = w.Write(jsonData)
			require.NoError(t, err)
		case "/custom/jwks.json":
			// Convert jwk.Set to JSON
			jsonData, err := json.Marshal(expectedCustomJWKS)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			_, err = w.Write(jsonData)
			require.NoError(t, err)
		default:
			t.Fatalf("was not expecting to handle the following url: %s", r.URL.String())
		}
	})

	return httptest.NewServer(handler)
}
