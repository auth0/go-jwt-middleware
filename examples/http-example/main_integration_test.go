package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPExample_ValidToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Valid token from the example
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.XFhrzWzntyINkgoRt2mb8dES84dJcuOoORdzKfwUX70"

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify response contains the custom claims
	assert.Contains(t, string(body), "John Doe")
	assert.Contains(t, string(body), "user123")
}

func TestHTTPExample_TokenWithShouldReject(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Token with shouldReject: true
	rejectToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyIsInNob3VsZFJlamVjdCI6dHJ1ZX0.Jf13PY_Oyu2x3Gx1JQ0jXRiWaCOb5T2RbKOrTPBNHJA"

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+rejectToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected due to custom validation
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHTTPExample_MissingToken(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHTTPExample_InvalidToken(t *testing.T) {
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

func TestHTTPExample_WrongIssuer(t *testing.T) {
	handler := setupHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Token with wrong issuer
	wrongIssuerToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3cm9uZy1pc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZS1leGFtcGxlIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMiwidXNlcm5hbWUiOiJ1c2VyMTIzIn0.8m4cV8KJFmKnHvY4I0F4Y9L8x-vH7RxQ1qvQzc6YZ8M"

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+wrongIssuerToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
