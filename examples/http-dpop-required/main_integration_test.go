package main

import (
	"context"
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

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/validator"
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
		jwtmiddleware.WithDPoPMode(jwtmiddleware.DPoPRequired),
		jwtmiddleware.WithDPoPProofOffset(60*time.Second),
		jwtmiddleware.WithDPoPIATLeeway(30*time.Second),
	)
	if err != nil {
		panic(err)
	}

	return middleware.CheckJWT(handler)
}

func TestDPoPRequired_ValidDPoPToken(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user123", "dpop-required-user")
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL+"/", accessToken)
	require.NoError(t, err)

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

	assert.Equal(t, "DPoP", response["token_type"])
	assert.Contains(t, response, "dpop_info")
}

func TestDPoPRequired_BearerTokenRejected(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	validToken := createBearerToken("user123", "dpop-required-user")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Bearer tokens cause token validation error in DPoP Required mode
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Equal(t, "invalid_request", response["error"])
}

func TestDPoPRequired_MissingToken(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Per RFC 6750 Section 3.1 + RFC 9449: When token is missing in DPoP Required mode,
	// should return ONLY DPoP challenge (no error codes, no Bearer challenge)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	assert.Len(t, wwwAuthHeaders, 1, "DPoP Required mode should only return one WWW-Authenticate header")

	wwwAuth := wwwAuthHeaders[0]
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "algs=")
	// Must NOT contain Bearer
	assert.NotContains(t, wwwAuth, "Bearer", "DPoP Required mode should not include Bearer challenge")
	// Per RFC 6750 Section 3.1, no error codes when auth is missing
	assert.NotContains(t, wwwAuth, "error=", "No error codes when auth is missing")
}

func TestDPoPRequired_DPoPTokenWithoutProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user123", "dpop-required-user")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Equal(t, "invalid_dpop_proof", response["error"])
}

func TestDPoPRequired_InvalidDPoPProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user123", "dpop-required-user")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", "invalid.proof.token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDPoPRequired_ExpiredDPoPProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user123", "dpop-required-user")
	require.NoError(t, err)

	oldTime := time.Now().Add(-2 * time.Minute)
	dpopProof, err := createDPoPProofWithTime(key, "GET", server.URL+"/", accessToken, oldTime)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Test that symmetric algorithms (HS256) are rejected for DPoP proofs
// Per RFC 9449, DPoP proofs MUST use asymmetric algorithms
func TestDPoPRequired_SymmetricAlgorithmRejected(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Create a symmetric key for signing
	symmetricKey := []byte("test-symmetric-key-for-dpop-proof")

	// Create access token (using the real JKT from an ECDSA key for the cnf claim)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	jkt, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	accessToken, err := createDPoPBoundToken(jkt, "user123", "dpop-required-user")
	require.NoError(t, err)

	// Create DPoP proof with HS256 (symmetric - should be rejected per RFC 9449)
	dpopProof, err := createDPoPProofWithOptions(symmetricKey, "GET", server.URL+"/", accessToken, time.Now(), jwa.HS256())
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail because DPoP proofs must use asymmetric algorithms
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &response)
	assert.Equal(t, "invalid_dpop_proof", response["error"])
}

// Test WWW-Authenticate header contains DPoP scheme with algs parameter
func TestDPoPRequired_WWWAuthenticateWithAlgs(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	// Send Bearer token to DPoP-required endpoint
	bearerToken := createBearerToken("user123", "read")

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Per RFC 9449, when DPoP is required, response should use DPoP scheme with algs
	// And should NOT include Bearer challenge (DPoP Required mode = DPoP only)
	wwwAuthHeaders := resp.Header.Values("WWW-Authenticate")
	require.Len(t, wwwAuthHeaders, 1, "DPoP Required mode should return exactly one WWW-Authenticate header (DPoP only, no Bearer)")

	wwwAuth := wwwAuthHeaders[0]
	// Must start with "DPoP " to be a DPoP challenge (not Bearer)
	assert.True(t, strings.HasPrefix(wwwAuth, "DPoP "), "WWW-Authenticate header must start with 'DPoP ' in DPoP Required mode")
	assert.Contains(t, wwwAuth, "algs=")
	// Should list supported asymmetric algorithms
	assert.Contains(t, wwwAuth, "ES256")
}

// =============================================================================
// Additional RFC 9449 Compliance Tests - REQUIRED Mode
// =============================================================================

// Bearer scheme with DPoP token and proof (rejected) → 400
func TestDPoPRequired_BearerScheme_DPoPToken_WithProof(t *testing.T) {
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

	dpopProof, err := createDPoPProof(key, "GET", server.URL, dpopToken)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+dpopToken) // Bearer scheme rejected in REQUIRED mode
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "invalid_request")

	// Verify only required headers
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Empty(t, resp.Header.Get("Authorization"))
}

// Empty Bearer with proof (rejected) → 400
func TestDPoPRequired_EmptyBearer_WithProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL, "")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ") // Empty
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "invalid_request")
}

// Bearer invalid token (rejected) → 400
func TestDPoPRequired_BearerInvalidToken(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "invalid_request")
}

// Bearer invalid token with proof (rejected) → 400
func TestDPoPRequired_BearerInvalidToken_WithProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL, "invalid.token.here")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "invalid_request")
}

// Bearer DPoP token (rejected) → 400
func TestDPoPRequired_BearerDPoPToken(t *testing.T) {
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
	req.Header.Set("Authorization", "Bearer "+dpopToken) // Bearer rejected

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "invalid_request")
}

// DPoP Bearer token (no cnf) with proof → 401
func TestDPoPRequired_DPoPScheme_BearerToken_WithProof(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	bearerToken := createBearerToken("user123", "read")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL, bearerToken)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "DPoP "+bearerToken) // Token missing cnf
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "invalid_token")
}

// Random scheme (rejected) → 400
func TestDPoPRequired_RandomScheme(t *testing.T) {
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

	dpopProof, err := createDPoPProof(key, "GET", server.URL, dpopToken)
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
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "invalid_request")
}

// Missing Authorization header → 400
func TestDPoPRequired_MissingAuthorization(t *testing.T) {
	h := setupHandler()
	server := httptest.NewServer(h)
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	dpopProof, err := createDPoPProof(key, "GET", server.URL, "")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("DPoP", dpopProof) // Only DPoP, no Authorization

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "DPoP")
	assert.Contains(t, wwwAuth, "invalid_request")
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

func createDPoPProof(key jwk.Key, httpMethod, httpURL, accessToken string) (string, error) {
	return createDPoPProofWithOptions(key, httpMethod, httpURL, accessToken, time.Now(), jwa.ES256())
}

func createDPoPProofWithTime(key jwk.Key, httpMethod, httpURL, accessToken string, timestamp time.Time) (string, error) {
	return createDPoPProofWithOptions(key, httpMethod, httpURL, accessToken, timestamp, jwa.ES256())
}

// createDPoPProofWithOptions creates a DPoP proof with configurable algorithm and timestamp
func createDPoPProofWithOptions(key any, httpMethod, httpURL, accessToken string, timestamp time.Time, alg jwa.SignatureAlgorithm) (string, error) {
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

	headers := jws.NewHeaders()
	headers.Set(jws.TypeKey, "dpop+jwt")

	// Only embed JWK for asymmetric algorithms (jwk.Key type)
	if jwkKey, ok := key.(jwk.Key); ok {
		headers.Set(jws.JWKKey, jwkKey)
	}

	signed, err := jwt.Sign(token,
		jwt.WithKey(alg, key, jws.WithProtectedHeaders(headers)),
	)
	if err != nil {
		return "", err
	}

	return string(signed), nil
}
