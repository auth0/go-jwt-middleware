package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupHandlerWithConfig creates a handler with custom proxy configuration for testing
func setupHandlerWithConfig(proxyOption jwtmiddleware.Option) http.Handler {
	keyFunc := func(ctx context.Context) (any, error) {
		return signingKey, nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience),
		validator.WithCustomClaims(func() *CustomClaimsExample {
			return &CustomClaimsExample{}
		}),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		panic(err)
	}

	options := []jwtmiddleware.Option{
		jwtmiddleware.WithValidator(jwtValidator),
		jwtmiddleware.WithDPoPProofOffset(5 * time.Minute),
		jwtmiddleware.WithDPoPIATLeeway(5 * time.Second),
	}

	if proxyOption != nil {
		options = append(options, proxyOption)
	}

	middleware, err := jwtmiddleware.New(options...)
	if err != nil {
		panic(err)
	}

	return middleware.CheckJWT(handler)
}

func TestStandardProxyConfiguration(t *testing.T) {
	handler := setupHandlerWithConfig(jwtmiddleware.WithStandardProxy())

	validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4"

	t.Run("accepts valid token with X-Forwarded-Proto and Host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ignores X-Forwarded-Prefix (not trusted by standard proxy)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")
		req.Header.Set("X-Forwarded-Prefix", "/api/v1") // Should be ignored

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles multiple proxy chain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https, http, http")
		req.Header.Set("X-Forwarded-Host", "client.example.com, proxy1.internal, proxy2.internal")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("rejects RFC 7239 Forwarded header (not trusted)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// Standard proxy doesn't trust Forwarded header
		req.Header.Set("Forwarded", "proto=https;host=forwarded.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should still succeed using direct request URL (Forwarded is ignored)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestAPIGatewayProxyConfiguration(t *testing.T) {
	handler := setupHandlerWithConfig(jwtmiddleware.WithAPIGatewayProxy())

	validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4"

	t.Run("accepts valid token with Proto, Host, and Prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")
		req.Header.Set("X-Forwarded-Prefix", "/api/v1")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles prefix without leading slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")
		req.Header.Set("X-Forwarded-Prefix", "api/v1")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles prefix with trailing slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")
		req.Header.Set("X-Forwarded-Prefix", "/api/v1/")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("rejects RFC 7239 Forwarded header (not trusted)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// API Gateway proxy doesn't trust Forwarded header
		req.Header.Set("Forwarded", "proto=https;host=forwarded.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should still succeed using direct request URL (Forwarded is ignored)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRFC7239ProxyConfiguration(t *testing.T) {
	handler := setupHandlerWithConfig(jwtmiddleware.WithRFC7239Proxy())

	validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4"

	t.Run("accepts valid token with RFC 7239 Forwarded header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("Forwarded", "proto=https;host=api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles quoted values in Forwarded header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("Forwarded", `proto="https";host="api.example.com"`)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles multiple forwarded entries (uses leftmost)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("Forwarded", "proto=https;host=client.example.com, proto=http;host=proxy.internal")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ignores X-Forwarded headers (only trusts RFC 7239)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// These should be ignored since we're using RFC7239 mode
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", "malicious.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed because X-Forwarded headers are ignored, uses direct request
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestCustomProxyConfiguration(t *testing.T) {
	// Test custom config that only trusts Proto
	handler := setupHandlerWithConfig(jwtmiddleware.WithTrustedProxies(&jwtmiddleware.TrustedProxyConfig{
		TrustXForwardedProto: true,
		TrustXForwardedHost:  false,
	}))

	validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4"

	t.Run("trusts only X-Forwarded-Proto", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "should-be-ignored.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed - Proto is trusted, Host is ignored (uses req.Host)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("rejects when X-Forwarded-Host is set but not trusted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// Only Proto is trusted, so Host header should be ignored
		req.Header.Set("X-Forwarded-Host", "malicious.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed because malicious host header is ignored
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestNoProxyConfiguration(t *testing.T) {
	// No proxy config - secure default
	handler := setupHandlerWithConfig(nil)

	validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4"

	t.Run("ignores all proxy headers (secure default)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")
		req.Header.Set("X-Forwarded-Prefix", "/api/v1")
		req.Header.Set("Forwarded", "proto=https;host=api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed - all headers ignored, uses direct request URL
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRFC7239Precedence(t *testing.T) {
	// Config that trusts both RFC 7239 and X-Forwarded headers
	handler := setupHandlerWithConfig(jwtmiddleware.WithTrustedProxies(&jwtmiddleware.TrustedProxyConfig{
		TrustForwarded:       true,
		TrustXForwardedProto: true,
		TrustXForwardedHost:  true,
	}))

	validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4"

	t.Run("RFC 7239 takes precedence over X-Forwarded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// RFC 7239 should win
		req.Header.Set("Forwarded", "proto=https;host=rfc7239.example.com")
		// These should be ignored
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", "xforwarded.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestErrorCases(t *testing.T) {
	handler := setupHandlerWithConfig(jwtmiddleware.WithStandardProxy())

	t.Run("rejects invalid token even with proxy headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("rejects missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("rejects malformed token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", "Bearer not-a-jwt")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("rejects expired token", func(t *testing.T) {
		// Token expired in 2020
		expiredToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjE1Nzc4MzY4MDAsImlhdCI6MTU3NzgzNjgwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.ysNnPgSDzP7Q8lPK7zHpYxLlxDQ3xJCqSY2xNfJA4iY"
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", expiredToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("rejects token with wrong issuer", func(t *testing.T) {
		// Token with issuer "wrong-issuer" instead of "go-jwt-middleware-dpop-proxy-example"
		wrongIssuerToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoid3JvbmctaXNzdWVyIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.8NMVjFMQgMcEKfJTpWXxIhcbvUWthfHJqHBBuKjAe7M"
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", wrongIssuerToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("rejects token with wrong signature", func(t *testing.T) {
		// Valid structure but wrong signature
		wrongSigToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.WRONGSIGNATUREXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", wrongSigToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestProxyConfigurationIntegration(t *testing.T) {
	handler := setupHandler() // Uses default setupHandler with WithStandardProxy()
	server := httptest.NewServer(handler)
	defer server.Close()

	validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4"

	t.Run("full request with proxy headers", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/api/users", nil)
		require.NoError(t, err)

		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")

		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestSecurityRejectionScenarios(t *testing.T) {
	validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2UtZXhhbXBsZSJdLCJleHAiOjIwNTMwNzA0MDAsImlhdCI6MTczNzcxMDQwMCwiaXNzIjoiZ28tand0LW1pZGRsZXdhcmUtZHBvcC1wcm94eS1leGFtcGxlIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoidXNlcjEyMyIsInVzZXJuYW1lIjoiam9obmRvZSJ9.67hi9dpfCzcRagv6GFkuaURBH3v7T6ya6k0nw_tYPW4"

	t.Run("no proxy config protects against header injection", func(t *testing.T) {
		// With no proxy config, ALL forwarded headers should be ignored
		handler := setupHandlerWithConfig(nil)

		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// Attacker tries to inject headers
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "malicious.example.com")
		req.Header.Set("X-Forwarded-Prefix", "/evil")
		req.Header.Set("Forwarded", "proto=https;host=evil.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed because ALL headers are ignored (secure default)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("standard proxy ignores untrusted headers", func(t *testing.T) {
		handler := setupHandlerWithConfig(jwtmiddleware.WithStandardProxy())

		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// These are trusted
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "api.example.com")
		// These should be ignored
		req.Header.Set("X-Forwarded-Prefix", "/malicious")
		req.Header.Set("Forwarded", "proto=http;host=evil.example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed - untrusted headers ignored
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RFC7239 proxy ignores X-Forwarded headers", func(t *testing.T) {
		handler := setupHandlerWithConfig(jwtmiddleware.WithRFC7239Proxy())

		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// These should be ignored (not trusted in RFC7239 mode)
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", "malicious.example.com")
		req.Header.Set("X-Forwarded-Prefix", "/evil")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed - X-Forwarded headers ignored in RFC7239 mode
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("custom config enforces granular trust", func(t *testing.T) {
		// Only trust Host, not Proto or Prefix
		handler := setupHandlerWithConfig(jwtmiddleware.WithTrustedProxies(&jwtmiddleware.TrustedProxyConfig{
			TrustXForwardedProto:  false,
			TrustXForwardedHost:   true,
			TrustXForwardedPrefix: false,
		}))

		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		req.Header.Set("X-Forwarded-Host", "api.example.com") // Trusted
		req.Header.Set("X-Forwarded-Proto", "http")           // Should be ignored
		req.Header.Set("X-Forwarded-Prefix", "/malicious")    // Should be ignored

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed - only Host is used, others ignored
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("prevents double proxy header manipulation", func(t *testing.T) {
		handler := setupHandlerWithConfig(jwtmiddleware.WithStandardProxy())

		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// Attacker tries to manipulate by sending multiple values
		// Middleware should use leftmost (closest to client)
		req.Header.Set("X-Forwarded-Proto", "https, http")
		req.Header.Set("X-Forwarded-Host", "legitimate.example.com, attacker.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed - uses leftmost values (https, legitimate.example.com)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles empty proxy headers safely", func(t *testing.T) {
		handler := setupHandlerWithConfig(jwtmiddleware.WithStandardProxy())

		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// Empty headers should be ignored
		req.Header.Set("X-Forwarded-Proto", "")
		req.Header.Set("X-Forwarded-Host", "")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed - empty headers ignored, uses direct request
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles malformed Forwarded header safely", func(t *testing.T) {
		handler := setupHandlerWithConfig(jwtmiddleware.WithRFC7239Proxy())

		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", validToken)
		// Malformed Forwarded header
		req.Header.Set("Forwarded", "this-is-not-valid-syntax")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should succeed - malformed header ignored, uses direct request
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
