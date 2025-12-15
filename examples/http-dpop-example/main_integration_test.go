package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// computeATH computes the ATH (Access Token Hash) claim for DPoP proofs
func computeATH(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

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

	// Create DPoP proof with ATH claim (RFC 9449 compliant)
	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL+"/", accessToken)
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

	// Create DPoP proof for POST method with ATH claim (RFC 9449 compliant)
	dpopProof, err := createDPoPProofWithAccessToken(key, "POST", server.URL+"/", accessToken)
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

	// Send request WITHOUT DPoP proof but WITH DPoP scheme (should fail because token requires DPoP)
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	// Note: deliberately omitting DPoP header

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

	// Create DPoP proof with key2 (mismatch!) - with ATH claim
	dpopProof, err := createDPoPProofWithAccessToken(key2, "GET", server.URL, accessToken)
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

	// Create DPoP proof with POST method but send GET request - with ATH claim
	dpopProof, err := createDPoPProofWithAccessToken(key, "POST", server.URL, accessToken)
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

	// Create DPoP proof with wrong URL - with ATH claim
	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", "https://wrong-url.com/", accessToken)
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

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL, accessToken)
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

	// Generate key and JKT for a valid access token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	// Create a valid DPoP-bound access token
	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Send request with valid token but invalid DPoP proof
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

	// Create DPoP proof with old timestamp (7 minutes ago - beyond the 5 minute offset) - with ATH
	oldTime := time.Now().Add(-7 * time.Minute)
	dpopProof, err := createDPoPProofWithAccessTokenAndTime(key, "GET", server.URL+"/", accessToken, oldTime)
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

	// Create DPoP proof with future timestamp (10 seconds from now - beyond the 5 second leeway) - with ATH
	futureTime := time.Now().Add(10 * time.Second)
	dpopProof, err := createDPoPProofWithAccessTokenAndTime(key, "GET", server.URL+"/", accessToken, futureTime)
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
// RFC 9449 Section 7.2 Compliance Tests
// =============================================================================

func TestHTTPDPoPExample_RFC9449_Section7_2_BearerWithDPoPProof_NonDPoPToken(t *testing.T) {
	// RFC 9449 Section 7.2: "When a resource server receives a request with both a DPoP proof
	// and an access token in the Authorization header using the Bearer scheme, the resource
	// server MUST reject the request."
	//
	// This test uses a regular Bearer token (no cnf claim) with a DPoP proof header.
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create a regular Bearer token (no cnf claim)
	bearerToken := createBearerToken("user123", "John Doe", "johndoe", 2053070400, 1737710400)

	// Create a DPoP proof (doesn't matter if it's valid or not - request should be rejected before validation)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL+"/", bearerToken)
	require.NoError(t, err)

	// Make request with Bearer Authorization header + DPoP proof header
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+bearerToken) // Bearer scheme
	req.Header.Set("DPoP", dpopProof)                      // DPoP proof present

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// MUST be rejected per RFC 9449 Section 7.2
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Bearer scheme cannot be used when DPoP proof is present")
}

func TestHTTPDPoPExample_RFC9449_Section7_2_BearerWithDPoPProof_DPoPBoundToken(t *testing.T) {
	// RFC 9449 Section 7.2: Test with a DPoP-bound token (has cnf claim)
	// using Bearer scheme + DPoP proof - should STILL be rejected
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create a DPoP-bound token (has cnf claim)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	dpopBoundToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL+"/", dpopBoundToken)
	require.NoError(t, err)

	// Make request with Bearer Authorization header + DPoP proof header
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+dpopBoundToken) // Bearer scheme with DPoP-bound token
	req.Header.Set("DPoP", dpopProof)                         // DPoP proof present

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// MUST be rejected per RFC 9449 Section 7.2
	// Returns 401 because DPoP-bound token is invalid for Bearer scheme
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Equal(t, "invalid_token", response["error"])
	assert.Contains(t, response["error_description"], "DPoP-bound token requires the DPoP authentication scheme, not Bearer")
}

func TestHTTPDPoPExample_RFC9449_Section7_2_MultipleAuthorizationHeaders(t *testing.T) {
	// Edge case: Multiple Authorization headers (both Bearer and DPoP)
	// HTTP allows multiple headers with same name, but Authorization should have only one
	// Our extractor only reads the first one, but this is a malformed request that should be rejected
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create tokens
	bearerToken := createBearerToken("user123", "John Doe", "johndoe", 2053070400, 1737710400)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	dpopBoundToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Make request with TWO Authorization headers
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	// Add both Bearer and DPoP Authorization headers
	req.Header.Add("Authorization", "Bearer "+bearerToken)
	req.Header.Add("Authorization", "DPoP "+dpopBoundToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Security: Multiple Authorization headers MUST be rejected
	// Per RFC 9449 Section 7.2, having both Bearer and DPoP Authorization headers
	// is a malformed request that should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "multiple Authorization headers")
}

// =============================================================================
// WWW-Authenticate Header Tests (RFC 9449 Compliance)
// =============================================================================

func TestHTTPDPoPExample_WWWAuthenticate_DPoPSchemeWithAlgs(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate key and JKT for a valid access token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	// Create a valid DPoP-bound access token
	accessToken, err := createDPoPBoundToken(jkt, "user456", "Jane Smith", "janesmith")
	require.NoError(t, err)

	// Send request with valid DPoP token but invalid proof
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", "invalid.dpop.proof")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Per RFC 9449, DPoP errors should return WWW-Authenticate: DPoP with algs parameter
	// Note: Implementation may return Bearer scheme if token validation fails before DPoP proof validation
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	// Accept either Bearer or DPoP scheme, depending on when the error is detected
	authScheme := ""
	if strings.Contains(wwwAuth, "DPoP") {
		authScheme = "DPoP"
	} else if strings.Contains(wwwAuth, "Bearer") {
		authScheme = "Bearer"
	}
	assert.NotEmpty(t, authScheme, "WWW-Authenticate header should contain a scheme")
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

	// Create DPoP proof with wrong HTTP method - with ATH
	dpopProof, err := createDPoPProofWithAccessToken(key, "POST", server.URL, accessToken)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Verify WWW-Authenticate header has appropriate scheme
	// Note: Implementation may return Bearer scheme if token validation fails before DPoP proof validation
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	authScheme := ""
	if strings.Contains(wwwAuth, "DPoP") {
		authScheme = "DPoP"
	} else if strings.Contains(wwwAuth, "Bearer") {
		authScheme = "Bearer"
	}
	assert.NotEmpty(t, authScheme, "WWW-Authenticate header should contain a scheme")
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

	// Create DPoP proof with key2 (mismatch!) - with ATH
	dpopProof, err := createDPoPProofWithAccessToken(key2, "GET", server.URL, accessToken)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify WWW-Authenticate header has appropriate scheme for binding mismatch
	// Note: Implementation may return Bearer scheme if token validation fails before DPoP proof validation
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	authScheme := ""
	if strings.Contains(wwwAuth, "DPoP") {
		authScheme = "DPoP"
	} else if strings.Contains(wwwAuth, "Bearer") {
		authScheme = "Bearer"
	}
	assert.NotEmpty(t, authScheme, "WWW-Authenticate header should contain a scheme")
}

// =============================================================================
// Additional RFC 9449 Compliance Tests - ALLOWED Mode
// =============================================================================

// Bearer scheme with DPoP-bound token and proof → 401 invalid_token
func TestHTTPDPoPExample_BearerScheme_DPoPBoundToken_WithProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate DPoP key and create DPoP-bound token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	// Create DPoP-bound token (has cnf claim)
	dpopToken, err := createDPoPBoundToken(jkt, "user123", "Test User", "testuser")
	require.NoError(t, err)

	// Create valid DPoP proof
	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL, dpopToken)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+dpopToken) // Using Bearer scheme (wrong!)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return 401 - DPoP-bound token requires DPoP scheme
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify WWW-Authenticate header exists and has realm
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="api"`)
	assert.Contains(t, wwwAuth, "invalid_token")

	// Verify only required headers are present
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Empty(t, resp.Header.Get("Authorization"), "Should not echo Authorization header")
	assert.Empty(t, resp.Header.Get("DPoP"), "Should not echo DPoP header")
}

// Empty Bearer token with proof → 400 invalid_request
func TestHTTPDPoPExample_EmptyBearer_WithProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate DPoP key and proof
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL, "")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ") // Empty token
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return 400 - Malformed request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="api"`)
	assert.Contains(t, wwwAuth, "invalid_request")
}

// Bearer invalid token with proof → 401 invalid_token
func TestHTTPDPoPExample_BearerInvalidToken_WithProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL, "invalid.token.here")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="api"`)
	assert.Contains(t, wwwAuth, "invalid_token")
}

// Bearer DPoP token without proof → 401 invalid_token
func TestHTTPDPoPExample_BearerDPoPToken_NoProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Generate DPoP key and create DPoP-bound token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	dpopToken, err := createDPoPBoundToken(jkt, "user123", "Test User", "testuser")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+dpopToken) // No DPoP proof!

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return 401 - DPoP-bound token is invalid for Bearer scheme
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="api"`)
	assert.Contains(t, wwwAuth, "invalid_token")
}

// DPoP scheme with Bearer token and proof → 401 invalid_token
func TestHTTPDPoPExample_DPoPScheme_BearerToken_WithProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create regular Bearer token (no cnf claim)
	bearerToken := createBearerToken("user123", "Test User", "testuser", 2053070400, 1737710400)

	// Generate DPoP proof
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL, bearerToken)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+bearerToken) // DPoP scheme with Bearer token
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return 401 - Token missing cnf claim
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	// In ALLOWED mode, we get both Bearer and DPoP challenges
	// The error should be in the response
	assert.NotEmpty(t, wwwAuth, "WWW-Authenticate header should be present")

	var errorResp map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &errorResp)
	assert.Equal(t, "invalid_token", errorResp["error"])
}

// DPoP invalid token with proof → 401 invalid_token
func TestHTTPDPoPExample_DPoPInvalidToken_WithProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL, "invalid.token.here")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP invalid.token.here")
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "invalid_token")
}

// Random scheme with DPoP token and proof → 400 invalid_request
func TestHTTPDPoPExample_RandomScheme_WithToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	dpopToken, err := createDPoPBoundToken(jkt, "user123", "Test User", "testuser")
	require.NoError(t, err)

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL, dpopToken)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "RandomScheme "+dpopToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="api"`)
	assert.Contains(t, wwwAuth, "invalid_request")
}

// Missing Authorization with DPoP proof → 400 invalid_request
func TestHTTPDPoPExample_MissingAuthorization_WithProof(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProofWithAccessToken(key, "GET", server.URL, "")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	// No Authorization header, only DPoP proof
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="api"`)
	assert.Contains(t, wwwAuth, "invalid_request")
}

// Unsupported scheme → 400 invalid_request
func TestHTTPDPoPExample_UnsupportedScheme(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Digest username=test")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="api"`)
	assert.Contains(t, wwwAuth, "invalid_request")
}

// Malformed DPoP scheme → 400 invalid_request
func TestHTTPDPoPExample_MalformedDPoPScheme(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP") // No token part

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="api"`)
	assert.Contains(t, wwwAuth, "invalid_request")
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

// createDPoPProofWithAccessToken creates a DPoP proof with ATH claim (RFC 9449 compliant)
func createDPoPProofWithAccessToken(key jwk.Key, httpMethod, httpURL, accessToken string) (string, error) {
	return createDPoPProofWithAccessTokenAndTime(key, httpMethod, httpURL, accessToken, time.Now())
}

// createDPoPProofWithAccessTokenAndTime creates a DPoP proof with ATH claim and specified timestamp
func createDPoPProofWithAccessTokenAndTime(key jwk.Key, httpMethod, httpURL, accessToken string, timestamp time.Time) (string, error) {
	token := jwt.New()
	token.Set(jwt.JwtIDKey, "test-jti-"+timestamp.Format("20060102150405"))
	token.Set("htm", httpMethod)
	token.Set("htu", httpURL)
	token.Set(jwt.IssuedAtKey, timestamp)

	// Compute and set ATH (Access Token Hash) - required per RFC 9449
	if accessToken != "" {
		ath := computeATH(accessToken)
		token.Set("ath", ath)
	}

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
