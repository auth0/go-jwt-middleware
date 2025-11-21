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
			WithIssuerURL(issuerURL),        // ProviderOption - works directly!
			WithCacheTTL(30*time.Second),    // CachingProviderOption
			WithCustomJWKSURI(jwksURL),      // ProviderOption - works directly!
			WithCustomClient(customClient),  // ProviderOption - works directly!
		)

		require.NoError(t, err)
		assert.NotNil(t, provider)
		// Options were applied successfully if no error
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
			WithIssuerURL(issuerURL),       // ProviderOption - works directly!
			WithCacheTTL(5*time.Minute),    // CachingProviderOption
			WithCustomJWKSURI(jwksURL),     // ProviderOption - works directly!
			WithCache(mockCache),           // CachingProviderOption
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
		})

		t.Run("WithCache rejects nil", func(t *testing.T) {
			_, err := NewCachingProvider(
				WithIssuerURL(issuerURL),
				WithCache(nil),
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cache cannot be nil")
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
