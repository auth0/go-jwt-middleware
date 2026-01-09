package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSetAndGetClaims tests the claims storage and retrieval from context
func TestSetAndGetClaims(t *testing.T) {
	t.Run("set and get claims successfully", func(t *testing.T) {
		ctx := context.Background()
		expectedClaims := map[string]any{"sub": "user123", "email": "user@example.com"}

		ctx = SetClaims(ctx, expectedClaims)
		claims, err := GetClaims[map[string]any](ctx)

		assert.NoError(t, err)
		assert.Equal(t, expectedClaims, claims)
	})

	t.Run("get claims with wrong type returns error", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetClaims(ctx, map[string]any{"sub": "user123"})

		_, err := GetClaims[string](ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "claims type assertion failed")
	})

	t.Run("get claims from empty context returns error", func(t *testing.T) {
		ctx := context.Background()

		_, err := GetClaims[map[string]any](ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "claims not found in context")
	})

	t.Run("has claims returns true when claims exist", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetClaims(ctx, map[string]any{"sub": "user123"})

		assert.True(t, HasClaims(ctx))
	})

	t.Run("has claims returns false when no claims", func(t *testing.T) {
		ctx := context.Background()

		assert.False(t, HasClaims(ctx))
	})
}

// TestSetAndGetDPoPContext tests the DPoP context storage and retrieval
func TestSetAndGetDPoPContext(t *testing.T) {
	t.Run("set and get DPoP context successfully", func(t *testing.T) {
		ctx := context.Background()
		expectedDPoPCtx := &DPoPContext{
			PublicKeyThumbprint: "test-jkt",
			IssuedAt:            time.Unix(1234567890, 0),
		}

		ctx = SetDPoPContext(ctx, expectedDPoPCtx)
		dpopCtx := GetDPoPContext(ctx)

		assert.NotNil(t, dpopCtx)
		assert.Equal(t, expectedDPoPCtx.PublicKeyThumbprint, dpopCtx.PublicKeyThumbprint)
		assert.Equal(t, expectedDPoPCtx.IssuedAt, dpopCtx.IssuedAt)
	})

	t.Run("get DPoP context from empty context returns nil", func(t *testing.T) {
		ctx := context.Background()

		dpopCtx := GetDPoPContext(ctx)

		assert.Nil(t, dpopCtx)
	})

	t.Run("has DPoP context returns true when context exists", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetDPoPContext(ctx, &DPoPContext{PublicKeyThumbprint: "test-jkt"})

		assert.True(t, HasDPoPContext(ctx))
	})

	t.Run("has DPoP context returns false when no context", func(t *testing.T) {
		ctx := context.Background()

		assert.False(t, HasDPoPContext(ctx))
	})
}

// TestSetAndGetAuthScheme tests the auth scheme storage and retrieval
func TestSetAndGetAuthScheme(t *testing.T) {
	t.Run("set and get Bearer scheme", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetAuthScheme(ctx, AuthSchemeBearer)

		scheme := GetAuthScheme(ctx)

		assert.Equal(t, AuthSchemeBearer, scheme)
	})

	t.Run("set and get DPoP scheme", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetAuthScheme(ctx, AuthSchemeDPoP)

		scheme := GetAuthScheme(ctx)

		assert.Equal(t, AuthSchemeDPoP, scheme)
	})

	t.Run("set and get Unknown scheme", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetAuthScheme(ctx, AuthSchemeUnknown)

		scheme := GetAuthScheme(ctx)

		assert.Equal(t, AuthSchemeUnknown, scheme)
	})

	t.Run("get scheme from empty context returns Unknown", func(t *testing.T) {
		ctx := context.Background()

		scheme := GetAuthScheme(ctx)

		assert.Equal(t, AuthSchemeUnknown, scheme)
	})

	t.Run("get scheme with invalid type in context returns Unknown", func(t *testing.T) {
		ctx := context.Background()
		// Manually insert wrong type to test defensive code
		ctx = context.WithValue(ctx, authSchemeKey, "invalid-type")

		scheme := GetAuthScheme(ctx)

		assert.Equal(t, AuthSchemeUnknown, scheme)
	})
}

// TestSetAndGetDPoPMode tests the DPoP mode storage and retrieval
func TestSetAndGetDPoPMode(t *testing.T) {
	t.Run("set and get DPoP Allowed mode", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetDPoPMode(ctx, DPoPAllowed)

		mode := GetDPoPMode(ctx)

		assert.Equal(t, DPoPAllowed, mode)
	})

	t.Run("set and get DPoP Required mode", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetDPoPMode(ctx, DPoPRequired)

		mode := GetDPoPMode(ctx)

		assert.Equal(t, DPoPRequired, mode)
	})

	t.Run("set and get DPoP Disabled mode", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetDPoPMode(ctx, DPoPDisabled)

		mode := GetDPoPMode(ctx)

		assert.Equal(t, DPoPDisabled, mode)
	})

	t.Run("get mode from empty context returns Allowed (default)", func(t *testing.T) {
		ctx := context.Background()

		mode := GetDPoPMode(ctx)

		assert.Equal(t, DPoPAllowed, mode)
	})

	t.Run("get mode with invalid type in context returns Allowed", func(t *testing.T) {
		ctx := context.Background()
		// Manually insert wrong type to test defensive code
		ctx = context.WithValue(ctx, dpopModeKey, "invalid-type")

		mode := GetDPoPMode(ctx)

		assert.Equal(t, DPoPAllowed, mode)
	})
}

// TestContextIsolation tests that context values are properly isolated
func TestContextIsolation(t *testing.T) {
	t.Run("different contexts have independent values", func(t *testing.T) {
		ctx1 := context.Background()
		ctx2 := context.Background()

		ctx1 = SetAuthScheme(ctx1, AuthSchemeBearer)
		ctx2 = SetAuthScheme(ctx2, AuthSchemeDPoP)

		scheme1 := GetAuthScheme(ctx1)
		scheme2 := GetAuthScheme(ctx2)

		assert.Equal(t, AuthSchemeBearer, scheme1)
		assert.Equal(t, AuthSchemeDPoP, scheme2)
	})

	t.Run("child context inherits parent values", func(t *testing.T) {
		parent := context.Background()
		parent = SetAuthScheme(parent, AuthSchemeBearer)

		child := SetDPoPMode(parent, DPoPRequired)

		// Child should have both parent and its own values
		assert.Equal(t, AuthSchemeBearer, GetAuthScheme(child))
		assert.Equal(t, DPoPRequired, GetDPoPMode(child))

		// Parent should only have its own value
		assert.Equal(t, AuthSchemeBearer, GetAuthScheme(parent))
		assert.Equal(t, DPoPAllowed, GetDPoPMode(parent)) // Default
	})
}
