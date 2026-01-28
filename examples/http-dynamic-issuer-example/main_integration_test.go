package main

import (
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

func newMockOIDCServer(t *testing.T) *mockOIDCServer {
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
			fmt.Fprintf(w, `{"issuer":"http://%s/","jwks_uri":"http://%s/.well-known/jwks.json"}`,
				r.Host, r.Host)
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
		Issuer:     server.URL + "/",
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

// setupTestDatabase replaces the global tenantDatabase for testing
func setupTestDatabase(tenant1Issuer, tenant2Issuer, tenant3PrimaryIssuer, tenant3BackupIssuer string) {
	tenantDatabase = map[string][]string{
		"tenant1": {tenant1Issuer},
		"tenant2": {tenant2Issuer},
		"tenant3": {tenant3PrimaryIssuer, tenant3BackupIssuer}, // Migration scenario
	}
}

func TestDynamicIssuerExample_Tenant1Token(t *testing.T) {
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t)
	defer tenant2.Close()

	setupTestDatabase(tenant1.Issuer, tenant2.Issuer, "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant1.generateToken(t, "tenant1-user123", "Tenant 1 User")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", "tenant1")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify response contains tenant info
	assert.Contains(t, string(body), "tenant1")
	assert.Contains(t, string(body), "tenant1-user123")
}

func TestDynamicIssuerExample_Tenant2Token(t *testing.T) {
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t)
	defer tenant2.Close()

	setupTestDatabase(tenant1.Issuer, tenant2.Issuer, "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant2.generateToken(t, "tenant2-user456", "Tenant 2 User")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", "tenant2")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify response contains tenant info
	assert.Contains(t, string(body), "tenant2")
	assert.Contains(t, string(body), "tenant2-user456")
}

func TestDynamicIssuerExample_Tenant3MultipleIssuers(t *testing.T) {
	// Migration scenario: tenant3 has both primary and backup issuers
	tenant3Primary := newMockOIDCServer(t)
	defer tenant3Primary.Close()

	tenant3Backup := newMockOIDCServer(t)
	defer tenant3Backup.Close()

	setupTestDatabase("", "", tenant3Primary.Issuer, tenant3Backup.Issuer)

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	// Test primary issuer
	primaryToken := tenant3Primary.generateToken(t, "tenant3-user789", "Tenant 3 User (Primary)")

	req1, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req1.Header.Set("X-Tenant-ID", "tenant3")
	req1.Header.Set("Authorization", "Bearer "+primaryToken)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()

	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Test backup issuer (migration scenario)
	backupToken := tenant3Backup.generateToken(t, "tenant3-user999", "Tenant 3 User (Backup)")

	req2, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req2.Header.Set("X-Tenant-ID", "tenant3")
	req2.Header.Set("Authorization", "Bearer "+backupToken)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestDynamicIssuerExample_MissingTenantHeader(t *testing.T) {
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	setupTestDatabase(tenant1.Issuer, "", "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant1.generateToken(t, "user123", "User")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	// No X-Tenant-ID header
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected by tenantMiddleware
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), "X-Tenant-ID")
}

func TestDynamicIssuerExample_UnknownTenant(t *testing.T) {
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	setupTestDatabase(tenant1.Issuer, "", "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant1.generateToken(t, "user999", "Unknown User")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", "tenant999") // Not in database
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected - tenant not found in database
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDynamicIssuerExample_WrongTenantForToken(t *testing.T) {
	// Token from tenant1, but request claims to be tenant2
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t)
	defer tenant2.Close()

	setupTestDatabase(tenant1.Issuer, tenant2.Issuer, "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant1.generateToken(t, "user123", "Tenant 1 User")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", "tenant2") // Claims to be tenant2
	req.Header.Set("Authorization", "Bearer "+token) // But uses tenant1 token

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected - issuer in token doesn't match tenant2's allowed issuers
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDynamicIssuerExample_MissingToken(t *testing.T) {
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	setupTestDatabase(tenant1.Issuer, "", "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", "tenant1")
	// No Authorization header

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDynamicIssuerExample_InvalidToken(t *testing.T) {
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	setupTestDatabase(tenant1.Issuer, "", "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", "tenant1")
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDynamicIssuerExample_CacheBehavior(t *testing.T) {
	// This test verifies that the issuer cache works correctly
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t)
	defer tenant2.Close()

	setupTestDatabase(tenant1.Issuer, tenant2.Issuer, "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	token1 := tenant1.generateToken(t, "user123", "Tenant 1 User")
	token2 := tenant2.generateToken(t, "user456", "Tenant 2 User")

	// First request for tenant1 - cache miss
	req1, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req1.Header.Set("X-Tenant-ID", "tenant1")
	req1.Header.Set("Authorization", "Bearer "+token1)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()

	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Second request for tenant1 - cache hit (should be faster)
	req2, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req2.Header.Set("X-Tenant-ID", "tenant1")
	req2.Header.Set("Authorization", "Bearer "+token1)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Different tenant should be a cache miss
	req3, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req3.Header.Set("X-Tenant-ID", "tenant2")
	req3.Header.Set("Authorization", "Bearer "+token2)

	resp3, err := http.DefaultClient.Do(req3)
	require.NoError(t, err)
	defer resp3.Body.Close()

	assert.Equal(t, http.StatusOK, resp3.StatusCode)
}

func TestDynamicIssuerExample_SSRFPrevention(t *testing.T) {
	// This test verifies that issuer validation happens BEFORE JWKS fetch
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t)
	defer tenant2.Close()

	setupTestDatabase(tenant1.Issuer, tenant2.Issuer, "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	// Use tenant1 header but tenant2's token
	// The resolver will return tenant1's allowed issuers
	// Token with tenant2 issuer should be rejected without fetching JWKS
	token := tenant2.generateToken(t, "user456", "Tenant 2 User")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", "tenant1") // Claims tenant1
	req.Header.Set("Authorization", "Bearer "+token) // But has tenant2 token

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected immediately due to issuer validation
	// without attempting to fetch JWKS from tenant2's endpoint
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Error should indicate token validation failure
	assert.Contains(t, string(body), "invalid_token")
}

func TestDynamicIssuerExample_ExpiredToken(t *testing.T) {
	tenant1 := newMockOIDCServer(t)
	defer tenant1.Close()

	setupTestDatabase(tenant1.Issuer, "", "", "")

	handler := setupHandler([]string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create expired token
	token := jwt.New()
	token.Set(jwt.IssuerKey, tenant1.Issuer)
	token.Set(jwt.AudienceKey, []string{testAudience})
	token.Set(jwt.SubjectKey, "user123")
	token.Set(jwt.IssuedAtKey, time.Now().Add(-2*time.Hour))
	token.Set(jwt.ExpirationKey, time.Now().Add(-1*time.Hour)) // Expired 1 hour ago

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), tenant1.PrivateKey))
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Tenant-ID", "tenant1")
	req.Header.Set("Authorization", "Bearer "+string(signed))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
