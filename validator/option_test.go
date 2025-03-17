package validator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWithAllowedClockSkew(t *testing.T) {
	v := &Validator{}
	skew := 5 * time.Minute
	
	err := WithAllowedClockSkew(skew)(v)
	
	assert.NoError(t, err)
	assert.Equal(t, skew, v.allowedClockSkew)
}

func TestWithCustomClaims(t *testing.T) {
	v := &Validator{}
	customClaimsFunc := func() CustomClaims {
		return &testClaims{Scope: "test"}
	}
	
	err := WithCustomClaims(customClaimsFunc)(v)
	
	assert.NoError(t, err)
	assert.NotNil(t, v.customClaims)
	
	// Verify the function was correctly stored
	claims := v.customClaims()
	assert.IsType(t, &testClaims{}, claims)
	assert.Equal(t, "test", claims.(*testClaims).Scope)
}

func TestWithExpectedIssuers(t *testing.T) {
	v := &Validator{
		expectedIssuers: []string{"original-issuer"},
	}
	
	newIssuers := []string{"issuer1", "issuer2"}
	err := WithExpectedIssuers(newIssuers)(v)
	
	assert.NoError(t, err)
	assert.Equal(t, newIssuers, v.expectedIssuers)
	
	// Test with empty issuers - should return error
	err = WithExpectedIssuers([]string{})(v)
	
	assert.Equal(t, ErrIssuerURLRequired, err)
	assert.Equal(t, newIssuers, v.expectedIssuers) // Should not have changed
}

func TestWithAdditionalIssuers(t *testing.T) {
	v := &Validator{
		expectedIssuers: []string{"issuer1"},
	}
	
	additionalIssuers := []string{"issuer2", "issuer3"}
	err := WithAdditionalIssuers(additionalIssuers)(v)
	
	assert.NoError(t, err)
	assert.Equal(t, []string{"issuer1", "issuer2", "issuer3"}, v.expectedIssuers)
	
	// Test with empty additional issuers - should succeed but not change anything
	err = WithAdditionalIssuers([]string{})(v)
	
	assert.NoError(t, err)
	assert.Equal(t, []string{"issuer1", "issuer2", "issuer3"}, v.expectedIssuers)
}

func TestWithSkipIssuerValidation(t *testing.T) {
	v := &Validator{
		skipIssuerValidation: false,
	}
	
	err := WithSkipIssuerValidation()(v)
	
	assert.NoError(t, err)
	assert.True(t, v.skipIssuerValidation)
}
