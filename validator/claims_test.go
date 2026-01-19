package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatedClaims_DPoPMethods(t *testing.T) {
	t.Run("GetConfirmationJKT returns empty when no cnf claim", func(t *testing.T) {
		claims := &ValidatedClaims{}
		jkt := claims.GetConfirmationJKT()
		assert.Empty(t, jkt)
	})

	t.Run("GetConfirmationJKT returns jkt from cnf claim", func(t *testing.T) {
		claims := &ValidatedClaims{
			ConfirmationClaim: &ConfirmationClaim{
				JKT: "test-jkt-value",
			},
		}
		jkt := claims.GetConfirmationJKT()
		assert.Equal(t, "test-jkt-value", jkt)
	})

	t.Run("GetConfirmationJKT returns empty when ConfirmationClaim is nil", func(t *testing.T) {
		claims := &ValidatedClaims{
			ConfirmationClaim: nil,
		}
		jkt := claims.GetConfirmationJKT()
		assert.Empty(t, jkt)
	})

	t.Run("HasConfirmation returns false when cnf is nil", func(t *testing.T) {
		claims := &ValidatedClaims{}
		has := claims.HasConfirmation()
		assert.False(t, has)
	})

	t.Run("HasConfirmation returns false when jkt is empty", func(t *testing.T) {
		claims := &ValidatedClaims{
			ConfirmationClaim: &ConfirmationClaim{
				JKT: "",
			},
		}
		has := claims.HasConfirmation()
		assert.False(t, has)
	})

	t.Run("HasConfirmation returns true when cnf has jkt", func(t *testing.T) {
		claims := &ValidatedClaims{
			ConfirmationClaim: &ConfirmationClaim{
				JKT: "test-jkt",
			},
		}
		has := claims.HasConfirmation()
		assert.True(t, has)
	})
}

func TestDPoPProofClaims_GetterMethods(t *testing.T) {
	t.Run("GetJTI returns the jti claim", func(t *testing.T) {
		claims := &DPoPProofClaims{
			JTI: "unique-id-123",
		}
		assert.Equal(t, "unique-id-123", claims.GetJTI())
	})

	t.Run("GetHTM returns the htm claim", func(t *testing.T) {
		claims := &DPoPProofClaims{
			HTM: "POST",
		}
		assert.Equal(t, "POST", claims.GetHTM())
	})

	t.Run("GetHTU returns the htu claim", func(t *testing.T) {
		claims := &DPoPProofClaims{
			HTU: "https://example.com/api",
		}
		assert.Equal(t, "https://example.com/api", claims.GetHTU())
	})

	t.Run("GetIAT returns the iat claim", func(t *testing.T) {
		claims := &DPoPProofClaims{
			IAT: 1234567890,
		}
		assert.Equal(t, int64(1234567890), claims.GetIAT())
	})

	t.Run("GetPublicKeyThumbprint returns the jkt", func(t *testing.T) {
		claims := &DPoPProofClaims{
			PublicKeyThumbprint: "thumbprint-value",
		}
		assert.Equal(t, "thumbprint-value", claims.GetPublicKeyThumbprint())
	})

	t.Run("GetPublicKey returns the public key", func(t *testing.T) {
		key := "test-public-key"
		claims := &DPoPProofClaims{
			PublicKey: key,
		}
		assert.Equal(t, key, claims.GetPublicKey())
	})
}
