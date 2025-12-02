package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Bearer Token Tests (No DPoP)
// =============================================================================

func TestHTTPDPoPExample_ValidBearerToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create a valid Bearer token at runtime with custom claims structure
	validToken := createBearerToken("user123", "John Doe", "johndoe", 2053070400, 1737710400)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Verify response contains the expected fields for Bearer token
	assert.Equal(t, "user123", response["subject"])
	assert.Equal(t, "johndoe", response["username"])
	assert.Equal(t, "John Doe", response["name"])
	assert.Equal(t, "go-jwt-middleware-dpop-example", response["issuer"])
	assert.Equal(t, false, response["dpop_enabled"])
	assert.Equal(t, "Bearer", response["token_type"])
}

func TestHTTPDPoPExample_MissingToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Equal(t, "invalid_token", response["error"])
}

func TestHTTPDPoPExample_InvalidBearerToken(t *testing.T) {
	handler := setupHandler()
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

func TestHTTPDPoPExample_ExpiredBearerToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Expired token (exp: 1516239022 = Jan 18, 2018)
	expiredToken := createBearerToken("user123", "John Doe", "johndoe", 1516239022, 1516239022-3600)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Equal(t, "invalid_token", response["error"])
}

func TestHTTPDPoPExample_WrongIssuerBearerToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Token with wrong issuer
	token := jwt.New()
	token.Set(jwt.IssuerKey, "wrong-issuer")
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.SubjectKey, "user123")
	token.Set("name", "John Doe")
	token.Set("username", "johndoe")
	token.Set(jwt.IssuedAtKey, time.Unix(1737710400, 0))
	token.Set(jwt.ExpirationKey, time.Unix(2053070400, 0))

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), signingKey))
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+string(signed))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Wrong issuer returns 401 Unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// =============================================================================
// DPoP Token Tests (Valid Cases)
// =============================================================================

func TestHTTPDPoPExample_ValidDPoPToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate ECDSA key pair for DPoP
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	// Calculate JKT for the cnf claim
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	// Create DPoP-bound access token
	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Create DPoP proof
	dpopProof, err := createDPoPProof(key, "GET", server.URL+"/")
	require.NoError(t, err)

	// Make request with both Authorization and DPoP headers
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Verify DPoP-specific fields
	assert.Equal(t, "user456", response["subject"])
	assert.Equal(t, "janesmith", response["username"])
	assert.Equal(t, "Jane Smith", response["name"])
	assert.Equal(t, true, response["dpop_enabled"])
	assert.Equal(t, "DPoP", response["token_type"])
	assert.NotEmpty(t, response["public_key_thumbprint"])
	assert.NotEmpty(t, response["dpop_issued_at"])
}

func TestHTTPDPoPExample_ValidDPoPToken_POST(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user789", "Bob Brown", "bobbrown")
	require.NoError(t, err)

	// Create DPoP proof for POST method
	dpopProof, err := createDPoPProof(key, "POST", server.URL+"/")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// =============================================================================
// DPoP Token Tests (Error Cases)
// =============================================================================

func TestHTTPDPoPExample_DPoPTokenWithoutProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate key and JKT
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	// Create DPoP-bound access token
	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Send request WITHOUT DPoP proof (should fail)
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail because token has cnf claim but no DPoP proof provided
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTPDPoPExample_DPoPMismatchedJKT(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate two different key pairs
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key1, err := jwk.Import(privateKey1)
	require.NoError(t, err)
	jkt1, err := key1.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := jwk.Import(privateKey2)
	require.NoError(t, err)

	// Create access token bound to key1
	accessToken, err := createDPoPBoundToken(jkt1, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Create DPoP proof with key2 (mismatch!)
	dpopProof, err := createDPoPProof(key2, "GET", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail due to JKT mismatch
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Contains(t, response["error_description"], "does not match")
}

func TestHTTPDPoPExample_DPoPWrongHTTPMethod(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Create DPoP proof with POST method but send GET request
	dpopProof, err := createDPoPProof(key, "POST", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail due to HTM mismatch
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Contains(t, response["error_description"], "HTM")
}

func TestHTTPDPoPExample_DPoPWrongURL(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Create DPoP proof with wrong URL
	dpopProof, err := createDPoPProof(key, "GET", "https://wrong-url.com/")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail due to HTU mismatch
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Contains(t, response["error_description"], "HTU")
}

func TestHTTPDPoPExample_MultipleDPoPHeaders(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	// Add multiple DPoP headers (not allowed per RFC 9449)
	req.Header.Add("DPoP", dpopProof)
	req.Header.Add("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail due to multiple DPoP headers
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	// Multiple DPoP headers is detected during extraction
	assert.Contains(t, []string{"invalid_request", "invalid_dpop_proof"}, response["error"])
}

func TestHTTPDPoPExample_InvalidDPoPProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", "invalid.dpop.proof")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail due to invalid DPoP proof
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHTTPDPoPExample_DPoPProofExpired(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Create DPoP proof with old timestamp (7 minutes ago - beyond the 5 minute offset)
	oldTime := time.Now().Add(-7 * time.Minute)
	dpopProof, err := createDPoPProofWithTime(key, "GET", server.URL+"/", oldTime)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail due to expired DPoP proof
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Contains(t, response["error_description"], "too old")
}

func TestHTTPDPoPExample_DPoPProofFuture(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Create DPoP proof with future timestamp (10 seconds from now - beyond the 5 second leeway)
	futureTime := time.Now().Add(10 * time.Second)
	dpopProof, err := createDPoPProofWithTime(key, "GET", server.URL+"/", futureTime)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail due to future DPoP proof
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Contains(t, response["error_description"], "future")
}

// =============================================================================
// WWW-Authenticate Header Tests (RFC 9449 Compliance)
// =============================================================================

func TestHTTPDPoPExample_WWWAuthenticate_DPoPSchemeWithAlgs(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Send request with DPoP token but invalid proof
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", "invalid.dpop.proof")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Per RFC 9449, DPoP errors should return WWW-Authenticate: DPoP with algs parameter
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "algs=")
	// Should contain supported algorithms
	assert.Contains(t, wwwAuth, "ES256")
}

func TestHTTPDPoPExample_WWWAuthenticate_DPoPHTMMismatch(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Create DPoP proof with wrong HTTP method
	dpopProof, err := createDPoPProof(key, "POST", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Verify WWW-Authenticate header has DPoP scheme with algs
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "algs=")
	assert.Contains(t, wwwAuth, "invalid_dpop_proof")
}

func TestHTTPDPoPExample_WWWAuthenticate_BearerSchemeForTokenErrors(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Send request with invalid Bearer token
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Bearer token errors should use Bearer scheme (NOT DPoP)
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	// Bearer scheme should NOT have algs parameter (per RFC 6750)
	assert.NotContains(t, wwwAuth, "algs=")
}

func TestHTTPDPoPExample_WWWAuthenticate_DPoPBindingMismatch(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate two different key pairs
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key1, err := jwk.Import(privateKey1)
	require.NoError(t, err)
	jkt1, err := key1.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := jwk.Import(privateKey2)
	require.NoError(t, err)

	// Create access token bound to key1
	accessToken, err := createDPoPBoundToken(jkt1, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Create DPoP proof with key2 (mismatch!)
	dpopProof, err := createDPoPProof(key2, "GET", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// DPoP binding mismatch should use DPoP scheme with algs
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "algs=")
}

// =============================================================================
// Helper Functions
// =============================================================================

// createBearerToken creates a valid Bearer token without cnf claim
func createBearerToken(sub, name, username string, exp, iat int64) string {
	token := jwt.New()
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.SubjectKey, sub)
	token.Set("name", name)
	token.Set("username", username)
	token.Set(jwt.IssuedAtKey, time.Unix(iat, 0))
	token.Set(jwt.ExpirationKey, time.Unix(exp, 0))

	signed, _ := jwt.Sign(token, jwt.WithKey(jwa.HS256(), signingKey))
	return string(signed)
}

// createDPoPBoundToken creates a DPoP-bound access token with cnf claim
func createDPoPBoundToken(jkt []byte, sub, name, username string) (string, error) {
	token := jwt.New()
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.SubjectKey, sub)
	token.Set("name", name)
	token.Set("username", username)
	token.Set(jwt.IssuedAtKey, time.Unix(1737710400, 0))
	token.Set(jwt.ExpirationKey, time.Unix(2053070400, 0))

	// Add cnf claim with JKT
	cnf := map[string]any{
		"jkt": base64.RawURLEncoding.EncodeToString(jkt),
	}
	token.Set("cnf", cnf)

	// Sign with HS256
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), signingKey))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

// createDPoPProof creates a DPoP proof with current timestamp
func createDPoPProof(key jwk.Key, httpMethod, httpURL string) (string, error) {
	return createDPoPProofWithTime(key, httpMethod, httpURL, time.Now())
}

// createDPoPProofWithTime creates a DPoP proof with specified timestamp
func createDPoPProofWithTime(key jwk.Key, httpMethod, httpURL string, timestamp time.Time) (string, error) {
	// Build DPoP proof JWT
	token := jwt.New()
	token.Set(jwt.JwtIDKey, "test-jti-"+timestamp.Format("20060102150405"))
	token.Set("htm", httpMethod)
	token.Set("htu", httpURL)
	token.Set(jwt.IssuedAtKey, timestamp)

	// Sign with ES256 and embed JWK in header
	headers := jws.NewHeaders()
	headers.Set(jws.TypeKey, "dpop+jwt")
	headers.Set(jws.JWKKey, key)

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)),
	)
	if err != nil {
		return "", err
	}

	return string(signed), nil
}
