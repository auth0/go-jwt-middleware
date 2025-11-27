package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testContextKey string

func TestDPoPContext_Helpers(t *testing.T) {
	t.Run("SetDPoPContext and GetDPoPContext", func(t *testing.T) {
		ctx := context.Background()

		dpopCtx := &DPoPContext{
			PublicKeyThumbprint: "test-jkt",
			IssuedAt:            time.Unix(1234567890, 0),
			TokenType:           "DPoP",
			PublicKey:           "test-key",
			DPoPProof:           "test-proof",
		}

		// Set DPoP context
		newCtx := SetDPoPContext(ctx, dpopCtx)
		require.NotNil(t, newCtx)

		// Get DPoP context
		retrieved := GetDPoPContext(newCtx)
		require.NotNil(t, retrieved)
		assert.Equal(t, dpopCtx.PublicKeyThumbprint, retrieved.PublicKeyThumbprint)
		assert.Equal(t, dpopCtx.IssuedAt, retrieved.IssuedAt)
		assert.Equal(t, dpopCtx.TokenType, retrieved.TokenType)
		assert.Equal(t, dpopCtx.PublicKey, retrieved.PublicKey)
		assert.Equal(t, dpopCtx.DPoPProof, retrieved.DPoPProof)
	})

	t.Run("GetDPoPContext returns nil when not set", func(t *testing.T) {
		ctx := context.Background()
		retrieved := GetDPoPContext(ctx)
		assert.Nil(t, retrieved)
	})

	t.Run("GetDPoPContext returns nil when wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), testContextKey("wrong"), "wrong-type")
		retrieved := GetDPoPContext(ctx)
		assert.Nil(t, retrieved)
	})

	t.Run("HasDPoPContext returns true when set", func(t *testing.T) {
		ctx := context.Background()
		dpopCtx := &DPoPContext{
			PublicKeyThumbprint: "test-jkt",
			IssuedAt:            time.Now(),
			TokenType:           "DPoP",
		}

		newCtx := SetDPoPContext(ctx, dpopCtx)
		assert.True(t, HasDPoPContext(newCtx))
	})

	t.Run("HasDPoPContext returns false when not set", func(t *testing.T) {
		ctx := context.Background()
		assert.False(t, HasDPoPContext(ctx))
	})

	t.Run("HasDPoPContext returns false when wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), testContextKey("wrong"), "wrong-type")
		assert.False(t, HasDPoPContext(ctx))
	})
}
