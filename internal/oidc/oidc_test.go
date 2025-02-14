package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// setupTestServer creates a test HTTP server that returns the specified response code and body.
func setupTestServer(responseCode int, responseBody string, headers map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, value := range headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(responseCode)
		_, _ = w.Write([]byte(responseBody))
	}))
}

// TestGetWellKnownEndpointsFromIssuerURL tests various scenarios for GetWellKnownEndpointsFromIssuerURL.
func TestGetWellKnownEndpointsFromIssuerURL(t *testing.T) {
	tests := []struct {
		name         string
		responseCode int
		responseBody string
		headers      map[string]string
		expectError  bool
	}{
		{
			name:         "Successful 200 response with valid JSON",
			responseCode: http.StatusOK,
			responseBody: `{"jwks_uri":"https://example.com/jwks"}`,
			headers:      map[string]string{"Content-Type": "application/json"},
			expectError:  false,
		},
		{
			name:         "404 Not Found response",
			responseCode: http.StatusNotFound,
			responseBody: `{"error": "not found"}`,
			expectError:  true,
		},
		{
			name:         "500 Internal Server Error response",
			responseCode: http.StatusInternalServerError,
			responseBody: `Internal Server Error`,
			expectError:  true,
		},
		{
			name:         "Malformed JSON response",
			responseCode: http.StatusOK,
			responseBody: `{"jwks_uri": "https://example.com/jwks"`, // Missing closing brace
			expectError:  true,
		},
		{
			name:         "Empty response",
			responseCode: http.StatusOK,
			responseBody: ``,
			expectError:  true,
		},
		{
			name:         "Non-JSON response",
			responseCode: http.StatusOK,
			responseBody: `<html><body>Error</body></html>`,
			headers:      map[string]string{"Content-Type": "text/html"},
			expectError:  true,
		},
		{
			name:         "Redirect response",
			responseCode: http.StatusFound,
			responseBody: "",
			expectError:  true,
		},
		{
			name:         "Unauthorized response",
			responseCode: http.StatusUnauthorized,
			responseBody: `{"error": "unauthorized"}`,
			expectError:  true,
		},
		{
			name:         "Forbidden response",
			responseCode: http.StatusForbidden,
			responseBody: `{"error": "forbidden"}`,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := setupTestServer(tt.responseCode, tt.responseBody, tt.headers)
			defer server.Close()

			issuerURL, _ := url.Parse(server.URL)
			ctx := context.Background()
			client := &http.Client{}
			_, err := GetWellKnownEndpointsFromIssuerURL(ctx, client, *issuerURL)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// Simulate a network failure scenario
func TestGetWellKnownEndpoints_NetworkError(t *testing.T) {
	client := &http.Client{}
	invalidURL, _ := url.Parse("http://invalid.local")
	_, err := GetWellKnownEndpointsFromIssuerURL(context.Background(), client, *invalidURL)

	if err == nil || !strings.Contains(err.Error(), "could not fetch well-known endpoints") {
		t.Errorf("Unexpected error: %v", err)
	}
}

// Simulate a timeout scenario
func TestGetWellKnownEndpoints_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	issuerURL, _ := url.Parse(server.URL)
	_, err := GetWellKnownEndpointsFromIssuerURL(context.Background(), client, *issuerURL)

	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

// Test invalid request creation
func TestGetWellKnownEndpoints_InvalidRequest(t *testing.T) {
	client := &http.Client{}

	invalidURL := url.URL{Scheme: ":", Host: ""}

	_, err := GetWellKnownEndpointsFromIssuerURL(context.Background(), client, invalidURL)

	if err == nil || !strings.Contains(err.Error(), "could not build request to get well-known endpoints") {
		t.Errorf("Expected request creation error, got: %v", err)
	}
}

// Test response body read failure
func TestGetWellKnownEndpoints_BodyReadFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
	}))
	server.CloseClientConnections()
	defer server.Close()

	client := &http.Client{}
	issuerURL, _ := url.Parse(server.URL)
	_, err := GetWellKnownEndpointsFromIssuerURL(context.Background(), client, *issuerURL)

	if err == nil || !strings.Contains(err.Error(), "failed to decode JSON") {
		t.Errorf("Expected body read failure error, got: %v", err)
	}
}
