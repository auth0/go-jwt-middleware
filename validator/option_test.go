package validator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptions(t *testing.T) {
	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}

	t.Run("WithKeyFunc", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			v := &Validator{}
			err := WithKeyFunc(keyFunc)(v)
			assert.NoError(t, err)
			assert.NotNil(t, v.keyFunc)
		})

		t.Run("nil keyFunc", func(t *testing.T) {
			v := &Validator{}
			err := WithKeyFunc(nil)(v)
			assert.Error(t, err)
			assert.Equal(t, ErrKeyFuncRequired, err)
		})
	})

	t.Run("WithSignatureAlgorithm", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			v := &Validator{}
			err := WithSignatureAlgorithm(HS256)(v)
			assert.NoError(t, err)
			assert.Equal(t, HS256, v.signatureAlgorithm)
		})

		t.Run("empty", func(t *testing.T) {
			v := &Validator{}
			err := WithSignatureAlgorithm("")(v)
			assert.Error(t, err)
			assert.Equal(t, ErrSignatureAlgRequired, err)
		})

		t.Run("unsupported", func(t *testing.T) {
			v := &Validator{}
			err := WithSignatureAlgorithm("INVALID")(v)
			assert.Error(t, err)
			assert.Equal(t, ErrUnsupportedAlgorithm, err)
		})
	})

	t.Run("Issuer Options", func(t *testing.T) {
		t.Run("WithIssuer", func(t *testing.T) {
			v := &Validator{}
			err := WithIssuer("issuer1")(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"issuer1"}, v.expectedIssuers)

			// Add another issuer
			err = WithIssuer("issuer2")(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"issuer1", "issuer2"}, v.expectedIssuers)
		})

		t.Run("WithIssuers", func(t *testing.T) {
			v := &Validator{}
			err := WithIssuers("issuer1", "issuer2")(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"issuer1", "issuer2"}, v.expectedIssuers)

			// Add more issuers
			err = WithIssuers("issuer3", "issuer4")(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"issuer1", "issuer2", "issuer3", "issuer4"}, v.expectedIssuers)
		})

		t.Run("WithReplaceIssuers", func(t *testing.T) {
			v := &Validator{
				expectedIssuers: []string{"issuer1", "issuer2"},
			}
			err := WithReplaceIssuers([]string{"new1", "new2"})(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"new1", "new2"}, v.expectedIssuers)
		})

		t.Run("WithExpectedIssuers alias", func(t *testing.T) {
			v1 := &Validator{
				expectedIssuers: []string{"issuer1", "issuer2"},
			}
			v2 := &Validator{
				expectedIssuers: []string{"issuer1", "issuer2"},
			}

			err1 := WithExpectedIssuers([]string{"new1", "new2"})(v1)
			err2 := WithReplaceIssuers([]string{"new1", "new2"})(v2)

			assert.NoError(t, err1)
			assert.NoError(t, err2)
			assert.Equal(t, v1.expectedIssuers, v2.expectedIssuers)
		})

		t.Run("WithAdditionalIssuers", func(t *testing.T) {
			v := &Validator{
				expectedIssuers: []string{"issuer1", "issuer2"},
			}
			err := WithAdditionalIssuers([]string{"add1", "add2"})(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"issuer1", "issuer2", "add1", "add2"}, v.expectedIssuers)
		})
	})

	t.Run("Audience Options", func(t *testing.T) {
		t.Run("WithAudience", func(t *testing.T) {
			v := &Validator{}
			err := WithAudience("audience1")(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"audience1"}, v.expectedAudience)

			// Add another audience
			err = WithAudience("audience2")(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"audience1", "audience2"}, v.expectedAudience)
		})

		t.Run("WithAudiences", func(t *testing.T) {
			v := &Validator{}
			err := WithAudiences("audience1", "audience2")(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"audience1", "audience2"}, v.expectedAudience)

			// Add more audiences
			err = WithAudiences("audience3", "audience4")(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"audience1", "audience2", "audience3", "audience4"}, v.expectedAudience)
		})

		t.Run("WithReplaceAudiences", func(t *testing.T) {
			v := &Validator{
				expectedAudience: []string{"audience1", "audience2"},
			}
			err := WithReplaceAudiences([]string{"new1", "new2"})(v)
			assert.NoError(t, err)
			assert.Equal(t, []string{"new1", "new2"}, v.expectedAudience)
		})
	})

	t.Run("WithAllowedClockSkew", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			v := &Validator{}
			err := WithAllowedClockSkew(5 * time.Second)(v)
			assert.NoError(t, err)
			assert.Equal(t, 5*time.Second, v.allowedClockSkew)
		})

		t.Run("zero", func(t *testing.T) {
			v := &Validator{}
			err := WithAllowedClockSkew(0)(v)
			assert.NoError(t, err)
			assert.Equal(t, time.Duration(0), v.allowedClockSkew)
		})

		t.Run("negative", func(t *testing.T) {
			v := &Validator{}
			err := WithAllowedClockSkew(-5 * time.Second)(v)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "clock skew cannot be negative")
		})
	})

	t.Run("WithCustomClaims", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			v := &Validator{}
			customClaimsFunc := func() CustomClaims {
				return &testClaims{}
			}
			err := WithCustomClaims(customClaimsFunc)(v)
			assert.NoError(t, err)
			assert.NotNil(t, v.customClaims)
		})

		t.Run("nil", func(t *testing.T) {
			v := &Validator{}
			err := WithCustomClaims(nil)(v)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "custom claims function cannot be nil")
		})
	})

	t.Run("WithSkipIssuerValidation", func(t *testing.T) {
		v := &Validator{}
		err := WithSkipIssuerValidation()(v)
		assert.NoError(t, err)
		assert.True(t, v.skipIssuerValidation)
	})

	t.Run("Creating validator with options", func(t *testing.T) {
		// Test creating a complete validator with all options
		validator, err := New(
			WithKeyFunc(keyFunc),
			WithSignatureAlgorithm(HS256),
			WithIssuer("https://issuer.example.com/"),
			WithAudiences("audience1", "audience2"),
			WithAllowedClockSkew(1 * time.Second),
			WithCustomClaims(func() CustomClaims {
				return &testClaims{}
			}),
		)
		
		require.NoError(t, err)
		assert.NotNil(t, validator)
		assert.Equal(t, []string{"https://issuer.example.com/"}, validator.expectedIssuers)
		assert.Equal(t, []string{"audience1", "audience2"}, validator.expectedAudience)
		assert.Equal(t, 1*time.Second, validator.allowedClockSkew)
		assert.NotNil(t, validator.customClaims)
	})
}
