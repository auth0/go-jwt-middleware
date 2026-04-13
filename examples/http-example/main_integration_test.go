package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

// errorResponse mirrors the DefaultErrorHandler JSON response structure.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCode        string `json:"error_code"`
}

// buildTestToken builds a signed HS256 JWT with the given claims.
func buildTestToken(t *testing.T, claims jwt.Claims, customClaims any) string {
	t.Helper()

	key := jose.SigningKey{Algorithm: jose.HS256, Key: signingKey}
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	builder := jwt.Signed(signer).Claims(claims)
	if customClaims != nil {
		builder = builder.Claims(customClaims)
	}

	token, err := builder.CompactSerialize()
	require.NoError(t, err)
	return token
}

// sendRequest sends a GET request to the test server with an optional Bearer token.
func sendRequest(t *testing.T, serverURL string, token string) (*http.Response, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, serverURL, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	return resp, body
}

// assertErrorResponse asserts the HTTP status, JSON error body, and WWW-Authenticate header.
func assertErrorResponse(
	t *testing.T,
	resp *http.Response,
	body []byte,
	wantStatus int,
	wantError string,
	wantErrorDesc string,
	wantErrorCode string,
) {
	t.Helper()

	assert.Equal(t, wantStatus, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var errResp errorResponse
	require.NoError(t, json.Unmarshal(body, &errResp))

	assert.Equal(t, wantError, errResp.Error)
	assert.Equal(t, wantErrorDesc, errResp.ErrorDescription)
	assert.Equal(t, wantErrorCode, errResp.ErrorCode)

	// Verify WWW-Authenticate header is present for auth errors
	if wantStatus == http.StatusUnauthorized || wantStatus == http.StatusForbidden {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		assert.NotEmpty(t, wwwAuth, "WWW-Authenticate header should be present")
		if wantErrorCode != "" {
			// Detailed error: WWW-Authenticate should contain the error type
			assert.Contains(t, wwwAuth, wantError)
		}
	}
}

// --- Tests ---

func TestHTTPExample_ValidToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Valid token from the example
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.XFhrzWzntyINkgoRt2mb8dES84dJcuOoORdzKfwUX70"

	resp, body := sendRequest(t, server.URL, validToken)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "John Doe")
	assert.Contains(t, string(body), "user123")
}

func TestHTTPExample_MissingToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	resp, body := sendRequest(t, server.URL, "")

	// Missing token: 401 with bare error (no description per RFC 6750 Section 3.1)
	assertErrorResponse(t, resp, body,
		http.StatusUnauthorized,
		"invalid_token",
		"", // no description for missing auth
		"", // no error_code for missing auth
	)
}

func TestHTTPExample_MalformedToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	resp, body := sendRequest(t, server.URL, "not.a.valid.jwt")

	assertErrorResponse(t, resp, body,
		http.StatusUnauthorized,
		"invalid_token",
		"The access token is malformed",
		"token_malformed",
	)
}

func TestHTTPExample_WrongIssuer(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Build a token signed with the correct key but wrong issuer
	token := buildTestToken(t, jwt.Claims{
		Issuer:   "wrong-issuer",
		Audience: audience,
	}, &CustomClaimsExample{Username: "user123"})

	resp, body := sendRequest(t, server.URL, token)

	assertErrorResponse(t, resp, body,
		http.StatusUnauthorized,
		"invalid_token",
		"The access token was issued by an untrusted issuer",
		"invalid_issuer",
	)
}

func TestHTTPExample_WrongAudience(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Build a token signed with the correct key but wrong audience
	token := buildTestToken(t, jwt.Claims{
		Issuer:   issuer,
		Audience: jwt.Audience{"wrong-audience"},
	}, &CustomClaimsExample{Username: "user123"})

	resp, body := sendRequest(t, server.URL, token)

	assertErrorResponse(t, resp, body,
		http.StatusUnauthorized,
		"invalid_token",
		"The access token audience does not match",
		"invalid_audience",
	)
}

func TestHTTPExample_ExpiredToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Build a token that expired in the past (beyond the 30s clock skew)
	token := buildTestToken(t, jwt.Claims{
		Issuer:   issuer,
		Audience: audience,
		Expiry:   jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
	}, &CustomClaimsExample{Username: "user123"})

	resp, body := sendRequest(t, server.URL, token)

	assertErrorResponse(t, resp, body,
		http.StatusUnauthorized,
		"invalid_token",
		"The access token expired",
		"token_expired",
	)
}

func TestHTTPExample_CustomClaimsRejected(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Build a token with shouldReject: true
	token := buildTestToken(t, jwt.Claims{
		Issuer:   issuer,
		Audience: audience,
	}, &CustomClaimsExample{
		Username:     "user123",
		ShouldReject: true,
	})

	resp, body := sendRequest(t, server.URL, token)

	assertErrorResponse(t, resp, body,
		http.StatusUnauthorized,
		"invalid_token",
		"The access token claims are invalid",
		"invalid_claims",
	)
}

func TestHTTPExample_InvalidToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Token signed with a different key
	wrongKey := jose.SigningKey{Algorithm: jose.HS256, Key: []byte("wrong-secret")}
	signer, err := jose.NewSigner(wrongKey, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuer,
		Audience: audience,
	}).CompactSerialize()
	require.NoError(t, err)

	resp, body := sendRequest(t, server.URL, token)

	// Wrong signature results in a token parsing failure
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var errResp errorResponse
	require.NoError(t, json.Unmarshal(body, &errResp))
	assert.Equal(t, "invalid_token", errResp.Error)
	assert.NotEmpty(t, errResp.ErrorCode)
}
