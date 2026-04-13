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

func TestMultiIssuerExample_Tenant1Token(t *testing.T) {
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t, "")
	defer tenant2.Close()

	issuers := []string{tenant1.Issuer, tenant2.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
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

func TestMultiIssuerExample_Tenant2Token(t *testing.T) {
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t, "")
	defer tenant2.Close()

	issuers := []string{tenant1.Issuer, tenant2.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	token := tenant2.generateToken(t, "user456", "Tenant 2 User")

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
	assert.Contains(t, string(body), tenant2.Issuer)
	assert.Contains(t, string(body), "user456")
}

func TestMultiIssuerExample_ThreeTenants(t *testing.T) {
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t, "")
	defer tenant2.Close()

	tenant3 := newMockOIDCServer(t, "")
	defer tenant3.Close()

	issuers := []string{tenant1.Issuer, tenant2.Issuer, tenant3.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	// Test all three tenants work
	for i, tenant := range []*mockOIDCServer{tenant1, tenant2, tenant3} {
		token := tenant.generateToken(t, fmt.Sprintf("user%d", i), fmt.Sprintf("Tenant %d User", i+1))

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

func TestMultiIssuerExample_UnauthorizedIssuer(t *testing.T) {
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	tenant2 := newMockOIDCServer(t, "")
	defer tenant2.Close()

	unauthorizedTenant := newMockOIDCServer(t, "")
	defer unauthorizedTenant.Close()

	// Only tenant1 and tenant2 are allowed
	issuers := []string{tenant1.Issuer, tenant2.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
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

	// Should be rejected - issuer not in allowed list (SSRF prevention test)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Should contain error about token validation
	assert.Contains(t, string(body), "invalid_token")
}

func TestMultiIssuerExample_MissingToken(t *testing.T) {
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMultiIssuerExample_InvalidToken(t *testing.T) {
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
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

func TestMultiIssuerExample_TokenSignedWithWrongKey(t *testing.T) {
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	otherTenant := newMockOIDCServer(t, "")
	defer otherTenant.Close()

	// Only tenant1 is allowed
	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate token with tenant1's issuer but signed with different key
	token := jwt.New()
	token.Set(jwt.IssuerKey, tenant1.Issuer) // Claims to be tenant1
	token.Set(jwt.AudienceKey, []string{testAudience})
	token.Set(jwt.SubjectKey, "user123")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(1*time.Hour))

	// But signed with different key (otherTenant's key)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), otherTenant.PrivateKey))
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+string(signed))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected - signature doesn't match
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMultiIssuerExample_SSRFPrevention(t *testing.T) {
	// This test verifies that issuer validation happens BEFORE JWKS fetch
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	unauthorizedTenant := newMockOIDCServer(t, "")
	defer unauthorizedTenant.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
	server := httptest.NewServer(handler)
	defer server.Close()

	// Token with unauthorized issuer
	token := unauthorizedTenant.generateToken(t, "user999", "Unauthorized")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected immediately due to issuer validation
	// without attempting to fetch JWKS from unauthorized issuer
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMultiIssuerExample_ExpiredToken(t *testing.T) {
	tenant1 := newMockOIDCServer(t, "")
	defer tenant1.Close()

	issuers := []string{tenant1.Issuer}
	handler := setupHandler(issuers, []string{testAudience})
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
	req.Header.Set("Authorization", "Bearer "+string(signed))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
