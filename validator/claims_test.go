package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestValidatedClaims_ActorHelpers(t *testing.T) {
	t.Run("no actor", func(t *testing.T) {
		claims := &ValidatedClaims{}
		assert.False(t, claims.HasActor())
		assert.Empty(t, claims.CurrentActor())

		chain, err := claims.DelegationChain()
		require.NoError(t, err)
		assert.Nil(t, chain)
	})

	t.Run("actor with empty subject is not considered present", func(t *testing.T) {
		claims := &ValidatedClaims{
			RegisteredClaims: RegisteredClaims{Act: &Actor{}},
		}
		assert.False(t, claims.HasActor())
		assert.Empty(t, claims.CurrentActor())

		// An empty subject at the head of the chain is malformed: DelegationChain
		// surfaces the error instead of silently returning an empty chain.
		chain, err := claims.DelegationChain()
		require.ErrorIs(t, err, ErrMalformedDelegationChain)
		assert.Empty(t, chain)
	})

	t.Run("empty subject in the middle of the chain surfaces an error", func(t *testing.T) {
		// Per RFC 8693 §4.1 verification does not fail on the actor claim, so the
		// malformed chain is caught here rather than at ValidateToken. The
		// subjects collected before the empty sub are returned alongside the error
		// so a caller learns the chain was truncated.
		claims := &ValidatedClaims{
			RegisteredClaims: RegisteredClaims{
				Act: &Actor{
					Subject: "mcp_server_client_id",
					Act:     &Actor{Subject: "", Act: &Actor{Subject: "spa_client_id"}},
				},
			},
		}

		chain, err := claims.DelegationChain()
		require.ErrorIs(t, err, ErrMalformedDelegationChain)
		assert.Equal(t, []string{"mcp_server_client_id"}, chain)
	})

	t.Run("single exchange", func(t *testing.T) {
		claims := &ValidatedClaims{
			RegisteredClaims: RegisteredClaims{
				Act: &Actor{
					Subject: "mcp_server_client_id",
					Act:     &Actor{Subject: "spa_client_id"},
				},
			},
		}

		assert.True(t, claims.HasActor())
		assert.Equal(t, "mcp_server_client_id", claims.CurrentActor())

		chain, err := claims.DelegationChain()
		require.NoError(t, err)
		assert.Equal(t, []string{"mcp_server_client_id", "spa_client_id"}, chain)
	})

	t.Run("chained exchange preserves order from current to original", func(t *testing.T) {
		claims := &ValidatedClaims{
			RegisteredClaims: RegisteredClaims{
				Act: &Actor{
					Subject: "mcp_server_2_client_id",
					Act: &Actor{
						Subject: "mcp_server_1_client_id",
						Act:     &Actor{Subject: "spa_client_id"},
					},
				},
			},
		}

		assert.Equal(t, "mcp_server_2_client_id", claims.CurrentActor())

		chain, err := claims.DelegationChain()
		require.NoError(t, err)
		assert.Equal(t,
			[]string{"mcp_server_2_client_id", "mcp_server_1_client_id", "spa_client_id"},
			chain,
		)
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
