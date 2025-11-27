package jwtmiddleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test DPoPHeaderExtractor
func TestDPoPHeaderExtractor(t *testing.T) {
	t.Run("extracts DPoP proof from header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("DPoP", "test-dpop-proof")

		proof, err := DPoPHeaderExtractor(req)

		require.NoError(t, err)
		assert.Equal(t, "test-dpop-proof", proof)
	})

	t.Run("returns empty string when no DPoP header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

		proof, err := DPoPHeaderExtractor(req)

		require.NoError(t, err)
		assert.Equal(t, "", proof)
	})

	t.Run("returns error for multiple DPoP headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Add("DPoP", "proof1")
		req.Header.Add("DPoP", "proof2")

		proof, err := DPoPHeaderExtractor(req)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "multiple DPoP headers are not allowed")
		assert.Equal(t, "", proof)
	})

	t.Run("handles empty DPoP header value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("DPoP", "")

		proof, err := DPoPHeaderExtractor(req)

		require.NoError(t, err)
		assert.Equal(t, "", proof)
	})
}

// Test DPoP context helpers

func TestGetDPoPContext(t *testing.T) {
	t.Run("returns DPoP context when present", func(t *testing.T) {
		expectedCtx := &core.DPoPContext{
			PublicKeyThumbprint: "test-jkt",
			IssuedAt:            time.Now(),
			TokenType:           "DPoP",
			PublicKey:           "test-key",
			DPoPProof:           "test-proof",
		}

		ctx := core.SetDPoPContext(context.Background(), expectedCtx)

		dpopCtx := GetDPoPContext(ctx)

		assert.NotNil(t, dpopCtx)
		assert.Equal(t, expectedCtx.PublicKeyThumbprint, dpopCtx.PublicKeyThumbprint)
		assert.Equal(t, expectedCtx.TokenType, dpopCtx.TokenType)
	})

	t.Run("returns nil when DPoP context not present", func(t *testing.T) {
		ctx := context.Background()

		dpopCtx := GetDPoPContext(ctx)

		assert.Nil(t, dpopCtx)
	})
}

func TestHasDPoPContext(t *testing.T) {
	t.Run("returns true when DPoP context exists", func(t *testing.T) {
		dpopCtx := &core.DPoPContext{
			PublicKeyThumbprint: "test-jkt",
		}
		ctx := core.SetDPoPContext(context.Background(), dpopCtx)

		assert.True(t, HasDPoPContext(ctx))
	})

	t.Run("returns false when DPoP context does not exist", func(t *testing.T) {
		ctx := context.Background()

		assert.False(t, HasDPoPContext(ctx))
	})
}

// Test AuthHeaderTokenExtractor with DPoP scheme

func TestAuthHeaderTokenExtractor_DPoP(t *testing.T) {
	t.Run("extracts token from DPoP authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Authorization", "DPoP test-access-token")

		token, err := AuthHeaderTokenExtractor(req)

		require.NoError(t, err)
		assert.Equal(t, "test-access-token", token)
	})

	t.Run("extracts token from Bearer authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Authorization", "Bearer test-access-token")

		token, err := AuthHeaderTokenExtractor(req)

		require.NoError(t, err)
		assert.Equal(t, "test-access-token", token)
	})

	t.Run("handles mixed case DPoP scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Authorization", "dpop test-access-token")

		token, err := AuthHeaderTokenExtractor(req)

		require.NoError(t, err)
		assert.Equal(t, "test-access-token", token)
	})

	t.Run("rejects invalid authorization scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

		token, err := AuthHeaderTokenExtractor(req)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization header format must be Bearer {token} or DPoP {token}")
		assert.Equal(t, "", token)
	})
}
