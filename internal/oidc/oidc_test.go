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
			responseBody: `{"issuer":"https://example.com","jwks_uri":"https://example.com/jwks"}`,
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
			_, err := GetWellKnownEndpointsFromIssuerURL(ctx, client, *issuerURL, "https://example.com")

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
	_, err := GetWellKnownEndpointsFromIssuerURL(context.Background(), client, *invalidURL, "http://invalid.local")

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
	_, err := GetWellKnownEndpointsFromIssuerURL(context.Background(), client, *issuerURL, server.URL)

	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

// Test invalid request creation
func TestGetWellKnownEndpoints_InvalidRequest(t *testing.T) {
	client := &http.Client{}

	invalidURL := url.URL{Scheme: ":", Host: ""}

	_, err := GetWellKnownEndpointsFromIssuerURL(context.Background(), client, invalidURL, "")

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
	_, err := GetWellKnownEndpointsFromIssuerURL(context.Background(), client, *issuerURL, server.URL)

	if err == nil || !strings.Contains(err.Error(), "failed to decode JSON") {
		t.Errorf("Expected body read failure error, got: %v", err)
	}
}

// TestGetWellKnownEndpointsFromIssuerURL_IssuerValidation tests the MCD double-validation requirement.
func TestGetWellKnownEndpointsFromIssuerURL_IssuerValidation(t *testing.T) {
	tests := []struct {
		name           string
		responseBody   string
		expectedIssuer string
		expectError    bool
		errorContains  string
	}{
		{
			name:           "Valid - issuer matches",
			responseBody:   `{"issuer":"https://tenant1.auth0.com/","jwks_uri":"https://tenant1.auth0.com/.well-known/jwks.json"}`,
			expectedIssuer: "https://tenant1.auth0.com/",
			expectError:    false,
		},
		{
			name:           "Invalid - issuer mismatch",
			responseBody:   `{"issuer":"https://attacker.com/","jwks_uri":"https://attacker.com/.well-known/jwks.json"}`,
			expectedIssuer: "https://tenant1.auth0.com/",
			expectError:    true,
			errorContains:  "issuer mismatch",
		},
		{
			name:           "Invalid - metadata missing issuer field",
			responseBody:   `{"jwks_uri":"https://tenant1.auth0.com/.well-known/jwks.json"}`,
			expectedIssuer: "https://tenant1.auth0.com/",
			expectError:    true,
			errorContains:  "missing required 'issuer' field",
		},
		{
			name:           "Invalid - metadata missing jwks_uri field",
			responseBody:   `{"issuer":"https://tenant1.auth0.com/"}`,
			expectedIssuer: "https://tenant1.auth0.com/",
			expectError:    true,
			errorContains:  "missing required 'jwks_uri' field",
		},
		{
			name:           "Invalid - empty issuer in metadata",
			responseBody:   `{"issuer":"","jwks_uri":"https://tenant1.auth0.com/.well-known/jwks.json"}`,
			expectedIssuer: "https://tenant1.auth0.com/",
			expectError:    true,
			errorContains:  "missing required 'issuer' field",
		},
		{
			name:           "Valid - different domain but issuer matches",
			responseBody:   `{"issuer":"https://custom-domain.example.com/","jwks_uri":"https://custom-domain.example.com/.well-known/jwks.json"}`,
			expectedIssuer: "https://custom-domain.example.com/",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := setupTestServer(http.StatusOK, tt.responseBody, map[string]string{"Content-Type": "application/json"})
			defer server.Close()

			client := &http.Client{}
			issuerURL, _ := url.Parse(server.URL)

			endpoints, err := GetWellKnownEndpointsFromIssuerURL(
				context.Background(),
				client,
				*issuerURL,
				tt.expectedIssuer,
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if endpoints == nil {
					t.Errorf("Expected endpoints but got nil")
				}
				if endpoints != nil && endpoints.Issuer != tt.expectedIssuer {
					t.Errorf("Expected issuer %q, got %q", tt.expectedIssuer, endpoints.Issuer)
				}
			}
		})
	}
}

// TestGetWellKnownEndpointsFromIssuerURL_SecurityScenarios tests security-focused scenarios.
func TestGetWellKnownEndpointsFromIssuerURL_SecurityScenarios(t *testing.T) {
	t.Run("Prevents token substitution attack", func(t *testing.T) {
		// Attacker tries to use a token from attacker.com with tenant1's JWKS
		responseBody := `{"issuer":"https://attacker.com/","jwks_uri":"https://attacker.com/.well-known/jwks.json"}`
		server := setupTestServer(http.StatusOK, responseBody, map[string]string{"Content-Type": "application/json"})
		defer server.Close()

		client := &http.Client{}
		issuerURL, _ := url.Parse(server.URL)

		// Token claims issuer is tenant1.auth0.com
		expectedIssuer := "https://tenant1.auth0.com/"

		_, err := GetWellKnownEndpointsFromIssuerURL(
			context.Background(),
			client,
			*issuerURL,
			expectedIssuer,
		)

		if err == nil {
			t.Error("Expected validation to fail for issuer mismatch")
		}
		if !strings.Contains(err.Error(), "issuer mismatch") {
			t.Errorf("Expected 'issuer mismatch' error, got: %v", err)
		}
	})

	t.Run("Allows legitimate multi-domain scenario", func(t *testing.T) {
		// Same tenant using custom domain - issuer must match exactly
		responseBody := `{"issuer":"https://custom.example.com/","jwks_uri":"https://custom.example.com/.well-known/jwks.json"}`
		server := setupTestServer(http.StatusOK, responseBody, map[string]string{"Content-Type": "application/json"})
		defer server.Close()

		client := &http.Client{}
		issuerURL, _ := url.Parse(server.URL)

		expectedIssuer := "https://custom.example.com/"

		endpoints, err := GetWellKnownEndpointsFromIssuerURL(
			context.Background(),
			client,
			*issuerURL,
			expectedIssuer,
		)

		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if endpoints == nil {
			t.Fatal("Expected endpoints but got nil")
		}
		if endpoints.Issuer != expectedIssuer {
			t.Errorf("Expected issuer %q, got %q", expectedIssuer, endpoints.Issuer)
		}
	})
}

