package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupHandler() http.Handler {
	keyFunc := func(ctx context.Context) (any, error) {
		return signingKey, nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience),
		validator.WithCustomClaims(func() *CustomClaims {
			return &CustomClaims{}
		}),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		panic(err)
	}

	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
		jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPDisabled),
	)
	if err != nil {
		panic(err)
	}

	return middleware.CheckJWT(handler)
}

// Bearer + valid_bearer_token → 200 OK
func TestDPoPDisabled_ValidBearerToken(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	validToken := createBearerToken("user123", "read:data")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Validate response contains expected data
	assert.Equal(t, "Bearer", response["token_type"])
	assert.Equal(t, "user123", response["subject"])
	assert.Equal(t, "read:data", response["scope"])

	// Verify no error headers
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

// Bearer + valid_dpop_token + valid_proof → 200 OK (DPoP ignored)
func TestDPoPDisabled_BearerDPoPToken_WithProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Generate DPoP-bound token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	dpopToken, err := createDPoPBoundToken(jkt, "user123", "read:data")
	require.NoError(t, err)

	// Generate DPoP proof
	dpopProof, err := createDPoPProof(key, "GET", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+dpopToken) // Bearer scheme
	req.Header.Set("DPoP", dpopProof)                    // DPoP proof ignored in DISABLED mode

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code - DPoP-bound tokens work as regular Bearer tokens in DISABLED mode
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// DPoP is disabled, so token works as Bearer (no DPoP validation)
	assert.Equal(t, "Bearer", response["token_type"])
	assert.Equal(t, "user123", response["subject"])

	// Verify no error headers
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

// Bearer + valid_dpop_token → 200 OK (DPoP-bound tokens work as Bearer)
func TestDPoPDisabled_BearerDPoPToken(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Generate DPoP-bound token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	dpopToken, err := createDPoPBoundToken(jkt, "user123", "read:data")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+dpopToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// DPoP-bound tokens work as regular Bearer tokens in DISABLED mode
	assert.Equal(t, "Bearer", response["token_type"])
	assert.Equal(t, "user123", response["subject"])

	// Verify no error headers
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

// DPoP + valid_dpop_token → 400 invalid_request
func TestDPoPDisabled_DPoPSchemeRejected(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user123", "read:data")
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL+"/")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// DPoP scheme not supported in DISABLED mode (unsupported authentication method)
	// Per RFC 6750 Section 3.1: error_description should be empty for unsupported authentication methods
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "dpop_not_allowed", response["error_code"])
	assert.Empty(t, response["error_description"], "error_description should be empty per RFC 6750 Section 3.1")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bare Bearer challenge (no error information per RFC 6750 Section 3.1 for unsupported authentication methods)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.NotContains(t, wwwAuthHeaders[0], "error=", "Unsupported authentication method should have bare challenge per RFC 6750 Section 3.1")
}

// Bearer + valid_bearer_token + DPoP header → 200 OK (DPoP header ignored)
func TestDPoPDisabled_BearerTokenWithDPoPHeaderIgnored(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	validToken := createBearerToken("user123", "read:data")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	dpopProof, err := createDPoPProof(key, "GET", server.URL+"/")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+validToken)
	req.Header.Set("DPoP", dpopProof) // DPoP header ignored in DISABLED mode

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// DPoP header ignored, token works as Bearer
	assert.Equal(t, "Bearer", response["token_type"])
	assert.Equal(t, "user123", response["subject"])
	assert.Equal(t, "read:data", response["scope"])

	// Verify no error headers
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

func TestDPoPDisabled_MissingToken(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Validate WWW-Authenticate header (bare Bearer challenge, no error)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Per RFC 6750 Section 3.1: No error codes when auth is missing
	// Verify it's Bearer challenge (not DPoP challenge)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.NotContains(t, wwwAuthHeaders[0], "error=", "No error codes when auth is missing")
}

// Bearer + invalid_token → 401 invalid_token
func TestDPoPDisabled_InvalidBearerToken(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Invalid token validation error
	assert.Equal(t, "invalid_token", response["error"])
	assert.NotEmpty(t, response["error_description"], "Token validation errors should have error_description")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bearer challenge should have error (verify it's Bearer, not DPoP challenge)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.Contains(t, wwwAuthHeaders[0], `error="invalid_token"`)
	assert.Contains(t, wwwAuthHeaders[0], `error_description=`)
}

func TestDPoPDisabled_ExpiredBearerToken(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	expiredToken := createExpiredBearerToken("user123", "read:data")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Expired token validation error
	assert.Equal(t, "invalid_token", response["error"])
	assert.NotEmpty(t, response["error_description"], "Token validation errors should have error_description")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bearer challenge should have error (verify it's Bearer, not DPoP challenge)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.Contains(t, wwwAuthHeaders[0], `error="invalid_token"`)
	assert.Contains(t, wwwAuthHeaders[0], `error_description=`)
}

// =============================================================================
// Additional RFC 9449 Compliance Tests - DISABLED Mode
// =============================================================================

// Empty Bearer with proof → 400 invalid_request
func TestDPoPDisabled_EmptyBearer_WithProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Generate DPoP proof
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ") // Empty token
	req.Header.Set("DPoP", dpopProof)           // Proof is ignored in DISABLED mode

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code - malformed request (empty token)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Malformed request error (empty Bearer token)
	// Per RFC 6750 Section 3.1: error_description should be empty for malformed requests
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "invalid_request", response["error_code"])
	assert.Empty(t, response["error_description"], "error_description should be empty per RFC 6750 Section 3.1")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bare Bearer challenge (no error information per RFC 6750 Section 3.1 for malformed requests)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.NotContains(t, wwwAuthHeaders[0], "error=", "Malformed request should have bare challenge per RFC 6750 Section 3.1")
}

// Bearer invalid token with proof → 401 invalid_token
func TestDPoPDisabled_BearerInvalidToken_WithProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Generate DPoP proof
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	req.Header.Set("DPoP", dpopProof) // Proof is ignored in DISABLED mode

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code - invalid token
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Invalid token validation error
	assert.Equal(t, "invalid_token", response["error"])
	assert.NotEmpty(t, response["error_description"], "Token validation errors should have error_description")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bearer challenge should have error (verify it's Bearer, not DPoP challenge)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.Contains(t, wwwAuthHeaders[0], `error="invalid_token"`)
	assert.Contains(t, wwwAuthHeaders[0], `error_description=`)
}

// DPoP invalid token with proof (rejected) → 400 invalid_request
func TestDPoPDisabled_DPoPInvalidToken_WithProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Generate DPoP proof
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP invalid.token.here")
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code - DPoP scheme rejected in DISABLED mode
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// DPoP scheme not allowed (unsupported authentication method)
	// Per RFC 6750 Section 3.1: error_description should be empty for unsupported authentication methods
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "dpop_not_allowed", response["error_code"])
	assert.Empty(t, response["error_description"], "error_description should be empty per RFC 6750 Section 3.1")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bare Bearer challenge (no error information per RFC 6750 Section 3.1 for unsupported authentication methods)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.NotContains(t, wwwAuthHeaders[0], "error=", "Unsupported authentication method should have bare challenge per RFC 6750 Section 3.1")
}

// DPoP token with invalid proof (rejected) → 400 invalid_request
func TestDPoPDisabled_DPoPToken_InvalidProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Generate DPoP-bound token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	dpopToken, err := createDPoPBoundToken(jkt, "user123", "read")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+dpopToken)
	req.Header.Set("DPoP", "invalid.proof.here")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code - DPoP scheme rejected in DISABLED mode
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// DPoP scheme not allowed (unsupported authentication method)
	// Per RFC 6750 Section 3.1: error_description should be empty for unsupported authentication methods
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "dpop_not_allowed", response["error_code"])
	assert.Empty(t, response["error_description"], "error_description should be empty per RFC 6750 Section 3.1")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bare Bearer challenge (no error information per RFC 6750 Section 3.1 for unsupported authentication methods)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.NotContains(t, wwwAuthHeaders[0], "error=", "Unsupported authentication method should have bare challenge per RFC 6750 Section 3.1")
}

// Random scheme (rejected) → 400 invalid_request
func TestDPoPDisabled_RandomScheme(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	validToken := createBearerToken("user123", "read")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "RandomScheme "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code - unsupported scheme
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Unsupported scheme (unsupported authentication method)
	// Per RFC 6750 Section 3.1: error_description should be empty for unsupported authentication methods
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "invalid_request", response["error_code"])
	assert.Empty(t, response["error_description"], "error_description should be empty per RFC 6750 Section 3.1")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bare Bearer challenge (no error information per RFC 6750 Section 3.1 for unsupported authentication methods)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.NotContains(t, wwwAuthHeaders[0], "error=", "Unsupported authentication method should have bare challenge per RFC 6750 Section 3.1")
}

// unsupported_scheme foo → 400 invalid_request
func TestDPoPDisabled_UnsupportedScheme(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "unsupported_scheme foo")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Unsupported scheme - malformed request
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "invalid_request", response["error_code"])
	// Note: error_description may be present for extraction errors
	// Per RFC 6750 Section 3.1, it's optional for invalid_request errors

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bearer challenge (verify it's Bearer, not DPoP challenge)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
}

// Malformed "DPoP dpop <valid_dpop_token>" → 400 invalid_request
func TestDPoPDisabled_MalformedDPoPScheme(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	dpopToken, err := createDPoPBoundToken(jkt, "user123", "read")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP dpop "+dpopToken) // Malformed

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Malformed request
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "invalid_request", response["error_code"])
	// Note: error_description may be present for extraction errors
	// Per RFC 6750 Section 3.1, it's optional for invalid_request errors

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bearer challenge (verify it's Bearer, not DPoP challenge)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
}

// (no Authorization) + valid_proof → 400 invalid_request
func TestDPoPDisabled_MissingAuthorization_WithProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Generate DPoP proof
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	// No Authorization header, only DPoP proof
	req.Header.Set("DPoP", dpopProof) // Proof is ignored in DISABLED mode

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Validate status code - DPoP proof requires Authorization header
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Validate response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]any
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	// Missing Authorization header with DPoP proof (malformed request)
	// Per RFC 6750 Section 3.1: error_description should be empty for malformed requests
	assert.Equal(t, "invalid_request", response["error"])
	assert.Equal(t, "invalid_request", response["error_code"])
	assert.Empty(t, response["error_description"], "error_description should be empty per RFC 6750 Section 3.1")

	// Validate WWW-Authenticate headers (Bearer only in DISABLED mode)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Disabled mode should return exactly one WWW-Authenticate header (Bearer only)")

	// Bare Bearer challenge (no error information per RFC 6750 Section 3.1 for malformed requests)
	assert.True(t, strings.HasPrefix(wwwAuthHeaders[0], "Bearer "), "WWW-Authenticate must be Bearer challenge, not DPoP")
	assert.Contains(t, wwwAuthHeaders[0], `realm="api"`)
	assert.NotContains(t, wwwAuthHeaders[0], "error=", "Malformed request should have bare challenge per RFC 6750 Section 3.1")
}

// Helper functions
func createBearerToken(sub, scope string) string {
	token := jwt.New()
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.SubjectKey, sub)
	token.Set("scope", scope)
	token.Set(jwt.IssuedAtKey, time.Unix(1737710400, 0))
	token.Set(jwt.ExpirationKey, time.Unix(2053070400, 0))

	signed, _ := jwt.Sign(token, jwt.WithKey(jwa.HS256(), signingKey))
	return string(signed)
}

func createExpiredBearerToken(sub, scope string) string {
	token := jwt.New()
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.SubjectKey, sub)
	token.Set("scope", scope)
	token.Set(jwt.IssuedAtKey, time.Unix(1609459200, 0))
	token.Set(jwt.ExpirationKey, time.Unix(1640995200, 0))

	signed, _ := jwt.Sign(token, jwt.WithKey(jwa.HS256(), signingKey))
	return string(signed)
}

func createDPoPBoundToken(jkt []byte, sub, scope string) (string, error) {
	token := jwt.New()
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.SubjectKey, sub)
	token.Set("scope", scope)
	token.Set(jwt.IssuedAtKey, time.Unix(1737710400, 0))
	token.Set(jwt.ExpirationKey, time.Unix(2053070400, 0))

	cnf := map[string]any{
		"jkt": base64.RawURLEncoding.EncodeToString(jkt),
	}
	token.Set("cnf", cnf)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), signingKey))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func createDPoPProof(key jwk.Key, httpMethod, httpURL string) (string, error) {
	token := jwt.New()
	token.Set(jwt.JwtIDKey, "test-jti-"+time.Now().Format("20060102150405"))
	token.Set("htm", httpMethod)
	token.Set("htu", httpURL)
	token.Set(jwt.IssuedAtKey, time.Now())

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
