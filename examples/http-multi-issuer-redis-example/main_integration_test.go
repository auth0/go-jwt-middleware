package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAudience = "https://api.example.com/"

// mockOIDCServer creates a mock OIDC/JWKS server for testing
type mockOIDCServer struct {
	*httptest.Server
	PrivateKey *rsa.PrivateKey
	PublicKey  jwk.Key
	Issuer     string
}

func newMockOIDCServer(t *testing.T, issuerPath string) *mockOIDCServer {
	// Generate RSA key pair for this issuer
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from public key using Import
	publicKey, err := jwk.Import(privateKey.PublicKey)
	require.NoError(t, err)
	publicKey.Set(jwk.KeyIDKey, "test-key-id")
	publicKey.Set(jwk.AlgorithmKey, jwa.RS256())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":"http://%s%s/","jwks_uri":"http://%s/.well-known/jwks.json"}`,
				r.Host, issuerPath, r.Host)
		} else if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")

			// Create JWK set
			set := jwk.NewSet()
			set.AddKey(publicKey)

			// Marshal to JSON using json.Marshal
			jsonData, _ := json.Marshal(set)
			w.Write(jsonData)
		} else {
			http.NotFound(w, r)
		}
	}))

	return &mockOIDCServer{
		Server:     server,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Issuer:     server.URL + issuerPath + "/",
	}
}

func (m *mockOIDCServer) generateToken(t *testing.T, subject, name string) string {
	token := jwt.New()
	token.Set(jwt.IssuerKey, m.Issuer)
	token.Set(jwt.AudienceKey, []string{testAudience})
	token.Set(jwt.SubjectKey, subject)
	token.Set("name", name)
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(1*time.Hour))

	// Create JWK key for signing (with kid)
	privateJWK, err := jwk.Import(m.PrivateKey)
	require.NoError(t, err)
	privateJWK.Set(jwk.KeyIDKey, "test-key-id") // Match the public key kid

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privateJWK))
	require.NoError(t, err)

	return string(signed)
}

// setupTestRedis creates a test Redis client and clears it
func setupTestRedis(t *testing.T) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use DB 1 for tests to avoid conflicts
	})

	ctx := context.Background()
	// Check if Redis is available
	err := client.Ping(ctx).Err()
	if err != nil {
		t.Skip("Redis not available - skipping test")
	}

	// Clear test database
	client.FlushDB(ctx)

	return client
}

func TestMultiIssuerRedisExample_BasicFlow(t *testing.T) {
	redisClient := setupTestRedis(t)
	defer redisClient.Close()

	redisCache := &RedisCache{
		client:     redisClient,
		ttl:        1 * time.Minute,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t, "")
	defer tenant2.Close()

	issuers := []string{tenant1.Issuer, tenant2.Issuer}
	handler := setupHandler(issuers, []string{testAudience}, redisCache)
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant1.generateToken(t, "user123", "Tenant 1 User")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify response contains issuer and subject
	assert.Contains(t, string(body), tenant1.Issuer)
	assert.Contains(t, string(body), "user123")
}

func TestMultiIssuerRedisExample_CacheHit(t *testing.T) {
	redisClient := setupTestRedis(t)
	defer redisClient.Close()

	redisCache := &RedisCache{
		client:     redisClient,
		ttl:        1 * time.Minute,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience}, redisCache)
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant1.generateToken(t, "user123", "Test User")

	// First request - cache miss, fetches from OIDC server
	req1, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req1.Header.Set("Authorization", "Bearer "+token)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Verify JWKS is now in Redis
	ctx := context.Background()
	jwksURI := tenant1.Issuer + ".well-known/jwks.json"
	cached, err := redisClient.Get(ctx, jwksURI).Result()
	require.NoError(t, err)
	assert.NotEmpty(t, cached)

	// Second request - cache hit, should use Redis
	req2, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestMultiIssuerRedisExample_MultipleTenants(t *testing.T) {
	redisClient := setupTestRedis(t)
	defer redisClient.Close()

	redisCache := &RedisCache{
		client:     redisClient,
		ttl:        1 * time.Minute,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t, "")
	defer tenant2.Close()

	tenant3 := newMockOIDCServer(t, "")
	defer tenant3.Close()

	issuers := []string{tenant1.Issuer, tenant2.Issuer, tenant3.Issuer}
	handler := setupHandler(issuers, []string{testAudience}, redisCache)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Test all three tenants work and cache in Redis
	for i, tenant := range []*mockOIDCServer{tenant1, tenant2, tenant3} {
		token := tenant.generateToken(t, fmt.Sprintf("user%d", i), fmt.Sprintf("Tenant %d User", i+1))

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify each tenant's JWKS is cached in Redis
		ctx := context.Background()
		jwksURI := tenant.Issuer + ".well-known/jwks.json"
		cached, err := redisClient.Get(ctx, jwksURI).Result()
		require.NoError(t, err)
		assert.NotEmpty(t, cached)
	}
}

func TestMultiIssuerRedisExample_UnauthorizedIssuer(t *testing.T) {
	redisClient := setupTestRedis(t)
	defer redisClient.Close()

	redisCache := &RedisCache{
		client:     redisClient,
		ttl:        1 * time.Minute,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t, "")
	defer tenant2.Close()

	unauthorizedTenant := newMockOIDCServer(t, "")
	defer unauthorizedTenant.Close()

	// Only tenant1 and tenant2 are allowed
	issuers := []string{tenant1.Issuer, tenant2.Issuer}
	handler := setupHandler(issuers, []string{testAudience}, redisCache)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Token from unauthorized issuer
	token := unauthorizedTenant.generateToken(t, "user999", "Unauthorized User")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected - issuer not in allowed list
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify unauthorized issuer's JWKS is NOT cached in Redis
	ctx := context.Background()
	jwksURI := unauthorizedTenant.Issuer + ".well-known/jwks.json"
	_, err = redisClient.Get(ctx, jwksURI).Result()
	assert.Equal(t, redis.Nil, err) // Should not exist in cache
}

func TestMultiIssuerRedisExample_CacheExpiration(t *testing.T) {
	redisClient := setupTestRedis(t)
	defer redisClient.Close()

	// Use very short TTL for testing expiration
	redisCache := &RedisCache{
		client:     redisClient,
		ttl:        1 * time.Second,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience}, redisCache)
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant1.generateToken(t, "user123", "Test User")

	// First request - cache JWKS
	req1, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req1.Header.Set("Authorization", "Bearer "+token)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Verify JWKS is in Redis
	ctx := context.Background()
	jwksURI := tenant1.Issuer + ".well-known/jwks.json"
	cached, err := redisClient.Get(ctx, jwksURI).Result()
	require.NoError(t, err)
	assert.NotEmpty(t, cached)

	// Wait for cache to expire
	time.Sleep(2 * time.Second)

	// Verify cache expired
	_, err = redisClient.Get(ctx, jwksURI).Result()
	assert.Equal(t, redis.Nil, err)

	// Second request should re-fetch and cache
	req2, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Verify JWKS is back in Redis
	cached2, err := redisClient.Get(ctx, jwksURI).Result()
	require.NoError(t, err)
	assert.NotEmpty(t, cached2)
}

func TestMultiIssuerRedisExample_ConcurrentRequests(t *testing.T) {
	redisClient := setupTestRedis(t)
	defer redisClient.Close()

	redisCache := &RedisCache{
		client:     redisClient,
		ttl:        1 * time.Minute,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience}, redisCache)
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant1.generateToken(t, "user123", "Test User")

	// Send concurrent requests
	const numRequests = 10
	errChan := make(chan error, numRequests)
	statusChan := make(chan int, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				errChan <- err
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errChan <- err
				return
			}
			defer resp.Body.Close()

			statusChan <- resp.StatusCode
			errChan <- nil
		}()
	}

	// Verify all requests succeeded
	for i := 0; i < numRequests; i++ {
		err := <-errChan
		assert.NoError(t, err)

		status := <-statusChan
		assert.Equal(t, http.StatusOK, status)
	}
}

func TestMultiIssuerRedisExample_MissingToken(t *testing.T) {
	redisClient := setupTestRedis(t)
	defer redisClient.Close()

	redisCache := &RedisCache{
		client:     redisClient,
		ttl:        1 * time.Minute,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience}, redisCache)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMultiIssuerRedisExample_InvalidToken(t *testing.T) {
	redisClient := setupTestRedis(t)
	defer redisClient.Close()

	redisCache := &RedisCache{
		client:     redisClient,
		ttl:        1 * time.Minute,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience}, redisCache)
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
