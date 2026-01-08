package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type mockTokenValidator struct {
	validateFunc     func(ctx context.Context, token string) (any, error)
	dpopValidateFunc func(ctx context.Context, proof string) (DPoPProofClaims, error)
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, token string) (any, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return &mockTokenClaims{}, nil
}

func (m *mockTokenValidator) ValidateDPoPProof(ctx context.Context, proof string) (DPoPProofClaims, error) {
	if m.dpopValidateFunc != nil {
		return m.dpopValidateFunc(ctx, proof)
	}
	return &mockDPoPProofClaims{}, nil
}

type mockTokenClaims struct {
	hasConfirmation bool
	jkt             string
}

func (m *mockTokenClaims) GetConfirmationJKT() string {
	return m.jkt
}

func (m *mockTokenClaims) HasConfirmation() bool {
	return m.hasConfirmation
}

type mockDPoPProofClaims struct {
	jti                 string
	htm                 string
	htu                 string
	iat                 int64
	publicKeyThumbprint string
	publicKey           any
	ath                 string
}

func (m *mockDPoPProofClaims) GetJTI() string                 { return m.jti }
func (m *mockDPoPProofClaims) GetHTM() string                 { return m.htm }
func (m *mockDPoPProofClaims) GetHTU() string                 { return m.htu }
func (m *mockDPoPProofClaims) GetIAT() int64                  { return m.iat }
func (m *mockDPoPProofClaims) GetPublicKeyThumbprint() string { return m.publicKeyThumbprint }
func (m *mockDPoPProofClaims) GetPublicKey() any              { return m.publicKey }
func (m *mockDPoPProofClaims) GetATH() string                 { return m.ath }

// Test Bearer token scenarios

func TestCheckTokenWithDPoP_BearerToken_Success(t *testing.T) {
	validator := &mockTokenValidator{}
	c, err := New(
		WithValidator(validator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"valid-bearer-token",
		AuthSchemeBearer,
		"", // No DPoP proof
		"",
		"",
	)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Nil(t, dpopCtx)
}

func TestCheckTokenWithDPoP_BearerTokenWithCnf_MissingProof(t *testing.T) {
	validator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             "test-jkt",
			}, nil
		},
	}
	c, err := New(
		WithValidator(validator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeBearer,
		"", // No DPoP proof provided
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	// Updated: Bearer scheme with DPoP-bound token (has cnf claim) is invalid_token (401)
	// DPoP-bound token requires the DPoP authentication scheme, not Bearer
	assert.ErrorIs(t, err, ErrJWTInvalid)
	assert.Contains(t, err.Error(), "DPoP-bound token requires the DPoP authentication scheme, not Bearer")
}

func TestCheckTokenWithDPoP_BearerToken_DPoPRequired(t *testing.T) {
	validator := &mockTokenValidator{}
	c, err := New(
		WithValidator(validator),
		WithDPoPMode(DPoPRequired),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"bearer-token",
		AuthSchemeBearer,
		"", // No DPoP proof
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	// Per RFC 6750 Section 3.1: Bearer scheme in Required mode returns invalid_request
	assert.ErrorIs(t, err, ErrInvalidRequest)
	// Verify error has no description (empty per RFC 6750 Section 3.1)
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		assert.Empty(t, validationErr.Message, "error_description should be empty for unsupported authentication method")
	}
}

func TestCheckTokenWithDPoP_EmptyToken_CredentialsOptional(t *testing.T) {
	validator := &mockTokenValidator{}
	c, err := New(
		WithValidator(validator),
		WithCredentialsOptional(true),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"", // Empty token
		AuthSchemeUnknown,
		"",
		"",
		"",
	)

	assert.NoError(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
}

func TestCheckTokenWithDPoP_EmptyToken_CredentialsRequired(t *testing.T) {
	validator := &mockTokenValidator{}
	c, err := New(
		WithValidator(validator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"", // Empty token
		AuthSchemeUnknown,
		"",
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.ErrorIs(t, err, ErrJWTMissing)
}

// Test DPoP token scenarios

func TestCheckTokenWithDPoP_DPoPToken_Success(t *testing.T) {
	now := time.Now().Unix()
	expectedJKT := "test-jkt-123"
	accessToken := "dpop-bound-token"
	// Compute expected ATH
	expectedATH := computeAccessTokenHash(accessToken)

	validator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             expectedJKT,
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return &mockDPoPProofClaims{
				jti:                 "unique-jti",
				htm:                 "GET",
				htu:                 "https://api.example.com/resource",
				iat:                 now,
				publicKeyThumbprint: expectedJKT,
				publicKey:           "mock-public-key",
				ath:                 expectedATH, // ATH is now required
			}, nil
		},
	}

	c, err := New(
		WithValidator(validator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		accessToken,
		AuthSchemeDPoP,
		"valid-dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.NotNil(t, dpopCtx)
	assert.Equal(t, expectedJKT, dpopCtx.PublicKeyThumbprint)
	assert.Equal(t, "DPoP", dpopCtx.TokenType)
	assert.Equal(t, time.Unix(now, 0), dpopCtx.IssuedAt)
}

func TestCheckTokenWithDPoP_DPoPToken_NoCnfClaim(t *testing.T) {
	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: false, // No cnf claim
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"bearer-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "cnf claim")
}

func TestCheckTokenWithDPoP_DPoPToken_JKTMismatch(t *testing.T) {
	now := time.Now().Unix()
	accessToken := "dpop-bound-token"
	expectedATH := computeAccessTokenHash(accessToken)

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             "expected-jkt",
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return &mockDPoPProofClaims{
				jti:                 "unique-jti",
				htm:                 "GET",
				htu:                 "https://api.example.com/resource",
				iat:                 now,
				publicKeyThumbprint: "different-jkt", // Mismatch!
				ath:                 expectedATH,
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "does not match")

	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		assert.Equal(t, ErrorCodeDPoPBindingMismatch, validationErr.Code)
	}
}

func TestCheckTokenWithDPoP_DPoPToken_HTMMismatch(t *testing.T) {
	now := time.Now().Unix()
	expectedJKT := "test-jkt"
	accessToken := "dpop-bound-token"
	expectedATH := computeAccessTokenHash(accessToken)

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             expectedJKT,
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return &mockDPoPProofClaims{
				jti:                 "unique-jti",
				htm:                 "POST", // Mismatch - expects GET
				htu:                 "https://api.example.com/resource",
				iat:                 now,
				publicKeyThumbprint: expectedJKT,
				ath:                 expectedATH,
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET", // Request method is GET
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "does not match request method")

	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		assert.Equal(t, ErrorCodeDPoPHTMMismatch, validationErr.Code)
	}
}

func TestCheckTokenWithDPoP_DPoPToken_HTUMismatch(t *testing.T) {
	now := time.Now().Unix()
	expectedJKT := "test-jkt"
	accessToken := "dpop-bound-token"
	expectedATH := computeAccessTokenHash(accessToken)

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             expectedJKT,
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return &mockDPoPProofClaims{
				jti:                 "unique-jti",
				htm:                 "GET",
				htu:                 "https://api.example.com/different", // Mismatch!
				iat:                 now,
				publicKeyThumbprint: expectedJKT,
				ath:                 expectedATH,
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource", // Different URL
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "does not match request URL")

	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		assert.Equal(t, ErrorCodeDPoPHTUMismatch, validationErr.Code)
	}
}

func TestCheckTokenWithDPoP_DPoPToken_IATExpired(t *testing.T) {
	expectedJKT := "test-jkt"
	oldIAT := time.Now().Unix() - 400 // 400 seconds ago (default offset is 300s)
	accessToken := "dpop-bound-token"
	expectedATH := computeAccessTokenHash(accessToken)

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             expectedJKT,
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return &mockDPoPProofClaims{
				jti:                 "unique-jti",
				htm:                 "GET",
				htu:                 "https://api.example.com/resource",
				iat:                 oldIAT, // Too old!
				publicKeyThumbprint: expectedJKT,
				ath:                 expectedATH,
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "too old")

	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		assert.Equal(t, ErrorCodeDPoPProofExpired, validationErr.Code)
	}
}

func TestCheckTokenWithDPoP_DPoPToken_IATTooNew(t *testing.T) {
	expectedJKT := "test-jkt"
	futureIAT := time.Now().Unix() + 60 // 60 seconds in future (default leeway is 30s)
	accessToken := "dpop-bound-token"
	expectedATH := computeAccessTokenHash(accessToken)

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             expectedJKT,
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return &mockDPoPProofClaims{
				jti:                 "unique-jti",
				htm:                 "GET",
				htu:                 "https://api.example.com/resource",
				iat:                 futureIAT, // Too far in future!
				publicKeyThumbprint: expectedJKT,
				ath:                 expectedATH,
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "too far in the future")

	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		assert.Equal(t, ErrorCodeDPoPProofTooNew, validationErr.Code)
	}
}

func TestCheckTokenWithDPoP_DPoPDisabled_IgnoresProof(t *testing.T) {
	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             "test-jkt",
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
		WithDPoPMode(DPoPDisabled),
	)
	require.NoError(t, err)

	// Using DPoP scheme when DPoP is disabled should be rejected (security)
	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeDPoP,
		"dpop-proof", // Proof is present
		"GET",
		"https://api.example.com/resource",
	)

	// Should fail because DPoP scheme is not allowed when DPoP is disabled
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.ErrorIs(t, err, ErrDPoPNotAllowed)
}

func TestCheckTokenWithDPoP_TokenValidationFails(t *testing.T) {
	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return nil, errors.New("token validation failed")
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"invalid-token",
		AuthSchemeBearer,
		"",
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "token validation failed")
}

func TestCheckTokenWithDPoP_DPoPProofValidationFails(t *testing.T) {
	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             "test-jkt",
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return nil, errors.New("proof validation failed")
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeDPoP,
		"invalid-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "DPoP proof is invalid")

	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		assert.Equal(t, ErrorCodeDPoPProofInvalid, validationErr.Code)
	}
}

func TestCheckTokenWithDPoP_NonTokenClaimsType(t *testing.T) {
	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			// Return a type that doesn't implement TokenClaims
			return map[string]any{"sub": "user123"}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"bearer-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.Contains(t, err.Error(), "do not support DPoP confirmation")
}

// Test DPoP mode

func TestDPoPMode_String(t *testing.T) {
	assert.Equal(t, "DPoPAllowed", DPoPAllowed.String())
	assert.Equal(t, "DPoPRequired", DPoPRequired.String())
	assert.Equal(t, "DPoPDisabled", DPoPDisabled.String())
	assert.Equal(t, "DPoPMode(99)", DPoPMode(99).String())
}

// Test DPoP configuration options

func TestWithDPoPMode(t *testing.T) {
	validator := &mockTokenValidator{}

	c, err := New(
		WithValidator(validator),
		WithDPoPMode(DPoPRequired),
	)

	require.NoError(t, err)
	assert.Equal(t, DPoPRequired, c.dpopMode)
}

func TestWithDPoPProofOffset(t *testing.T) {
	validator := &mockTokenValidator{}

	c, err := New(
		WithValidator(validator),
		WithDPoPProofOffset(60*time.Second),
	)

	require.NoError(t, err)
	assert.Equal(t, 60*time.Second, c.dpopProofOffset)
}

func TestWithDPoPProofOffset_Negative(t *testing.T) {
	validator := &mockTokenValidator{}

	_, err := New(
		WithValidator(validator),
		WithDPoPProofOffset(-10*time.Second),
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be negative")
}

func TestWithDPoPIATLeeway(t *testing.T) {
	validator := &mockTokenValidator{}

	c, err := New(
		WithValidator(validator),
		WithDPoPIATLeeway(10*time.Second),
	)

	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, c.dpopIATLeeway)
}

func TestWithDPoPIATLeeway_Negative(t *testing.T) {
	validator := &mockTokenValidator{}

	_, err := New(
		WithValidator(validator),
		WithDPoPIATLeeway(-5*time.Second),
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be negative")
}

// Test with logger to cover logger code paths

func TestCheckTokenWithDPoP_WithLogger_Success(t *testing.T) {
	now := time.Now().Unix()
	expectedJKT := "test-jkt-123"
	accessToken := "dpop-bound-token"
	expectedATH := computeAccessTokenHash(accessToken)
	logger := &mockLogger{}

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             expectedJKT,
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return &mockDPoPProofClaims{
				jti:                 "unique-jti",
				htm:                 "GET",
				htu:                 "https://api.example.com/resource",
				iat:                 now,
				publicKeyThumbprint: expectedJKT,
				publicKey:           "mock-public-key",
				ath:                 expectedATH,
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
		WithLogger(logger),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		accessToken,
		AuthSchemeDPoP,
		"valid-dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.NotNil(t, dpopCtx)
	require.NotEmpty(t, logger.infoCalls)
	assert.Equal(t, "DPoP token validated successfully", logger.infoCalls[0].msg)
}

func TestCheckTokenWithDPoP_WithLogger_BearerAccepted(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockTokenValidator{}

	c, err := New(
		WithValidator(validator),
		WithLogger(logger),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"bearer-token",
		AuthSchemeBearer,
		"",
		"",
		"",
	)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.debugCalls)
	// Check that "Bearer token accepted" appears in the debug logs
	found := false
	for _, call := range logger.debugCalls {
		if call.msg == "Bearer token accepted" {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected 'Bearer token accepted' in debug logs")
}

func TestCheckTokenWithDPoP_WithLogger_MissingProof(t *testing.T) {
	logger := &mockLogger{}

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             "test-jkt",
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
		WithLogger(logger),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeBearer,
		"", // No proof
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.errorCalls)
	// Token has cnf but no DPoP proof with Bearer scheme → invalid_token error
	assert.Equal(t, "DPoP-bound token requires the DPoP authentication scheme, not Bearer", logger.errorCalls[0].msg)
}

func TestCheckTokenWithDPoP_WithLogger_BearerNotAllowed(t *testing.T) {
	logger := &mockLogger{}
	validator := &mockTokenValidator{}

	c, err := New(
		WithValidator(validator),
		WithDPoPMode(DPoPRequired),
		WithLogger(logger),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"bearer-token",
		AuthSchemeBearer,
		"",
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.errorCalls)
	assert.Equal(t, "Bearer authorization scheme used but DPoP Required mode only accepts DPoP scheme", logger.errorCalls[0].msg)
}

func TestCheckTokenWithDPoP_WithLogger_DPoPDisabled(t *testing.T) {
	logger := &mockLogger{}

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             "test-jkt",
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
		WithDPoPMode(DPoPDisabled),
		WithLogger(logger),
	)
	require.NoError(t, err)

	// Using DPoP scheme when DPoP is disabled should be rejected (security)
	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	// Should log error about DPoP scheme being used when disabled
	require.NotEmpty(t, logger.errorCalls)
	assert.Equal(t, "DPoP authorization scheme used but DPoP is disabled", logger.errorCalls[0].msg)
}

func TestCheckTokenWithDPoP_WithLogger_NoCnfClaim(t *testing.T) {
	logger := &mockLogger{}

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: false,
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
		WithLogger(logger),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"bearer-token",
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.errorCalls)
	// RFC 9449 Section 7.1: DPoP scheme requires DPoP-bound token (with cnf claim)
	assert.Equal(t, "DPoP authorization scheme used with non-DPoP-bound token (missing cnf claim)", logger.errorCalls[0].msg)
}

func TestCheckTokenWithDPoP_WithLogger_JKTMismatch(t *testing.T) {
	now := time.Now().Unix()
	accessToken := "dpop-bound-token"
	expectedATH := computeAccessTokenHash(accessToken)
	logger := &mockLogger{}

	tokenValidator := &mockTokenValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return &mockTokenClaims{
				hasConfirmation: true,
				jkt:             "expected-jkt",
			}, nil
		},
		dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
			return &mockDPoPProofClaims{
				jti:                 "unique-jti",
				htm:                 "GET",
				htu:                 "https://api.example.com/resource",
				iat:                 now,
				publicKeyThumbprint: "different-jkt",
				ath:                 expectedATH,
			}, nil
		},
	}

	c, err := New(
		WithValidator(tokenValidator),
		WithLogger(logger),
	)
	require.NoError(t, err)

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		accessToken,
		AuthSchemeDPoP,
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.errorCalls)
	assert.Equal(t, "DPoP JKT mismatch", logger.errorCalls[0].msg)
}

// TestCheckTokenWithDPoP_EdgeCases tests additional edge cases
func TestCheckTokenWithDPoP_EdgeCases(t *testing.T) {
	t.Run("token validator returns error", func(t *testing.T) {
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return nil, errors.New("token validation failed")
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"invalid-token",
			AuthSchemeBearer,
			"",
			"",
			"",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "token validation failed")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)
	})

	// DPoP validator error is already covered in other test cases

	t.Run("claims without confirmation and no dpop proof - succeeds", func(t *testing.T) {
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: false,
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"token",
			AuthSchemeBearer,
			"",
			"POST",
			"https://example.com",
		)

		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Nil(t, dpopCtx)
	})

	t.Run("claims with cnf but empty jkt - error", func(t *testing.T) {
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "",
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"token",
			AuthSchemeBearer,
			"",
			"POST",
			"https://example.com",
		)

		// Token has cnf claim but no DPoP proof with Bearer scheme → invalid_token (401)
		// DPoP-bound token requires the DPoP authentication scheme, not Bearer
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJWTInvalid)
		assert.Contains(t, err.Error(), "DPoP-bound token requires the DPoP authentication scheme, not Bearer")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			assert.Equal(t, ErrorCodeInvalidToken, validationErr.Code)
		}
	})

	t.Run("cnf claim with missing dpop proof - error", func(t *testing.T) {
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"token",
			AuthSchemeBearer,
			"", // No DPoP proof
			"POST",
			"https://example.com",
		)

		// Token has cnf claim but no DPoP proof with Bearer scheme → invalid_token (401)
		// DPoP-bound token requires the DPoP authentication scheme, not Bearer
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJWTInvalid)
		assert.Contains(t, err.Error(), "DPoP-bound token requires the DPoP authentication scheme, not Bearer")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			assert.Equal(t, ErrorCodeInvalidToken, validationErr.Code)
		}
	})

	t.Run("thumbprint mismatch - error", func(t *testing.T) {
		accessToken := "token"
		expectedATH := computeAccessTokenHash(accessToken)

		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "expected-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "different-jkt",
					ath:                 expectedATH,
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"token",
			AuthSchemeDPoP,
			"proof",
			"POST",
			"https://example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)
	})

	t.Run("DPoP disabled with Bearer scheme and cnf claim - success", func(t *testing.T) {
		// RFC 9449 Section 7.2: "A protected resource that supports only [RFC6750] and is unaware
		// of DPoP would most presumably accept a DPoP-bound access token as a bearer token"
		// When DPoP is disabled, the server ignores cnf claims and DPoP headers
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
			WithDPoPMode(DPoPDisabled),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"dpop-bound-token",
			AuthSchemeBearer, // Bearer scheme
			"dpop-proof",     // DPoP proof present (but ignored)
			"POST",
			"https://example.com",
		)

		// DPoP disabled = server unaware of DPoP = accepts DPoP-bound token as bearer
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Nil(t, dpopCtx) // No DPoP context when DPoP is disabled
	})

	t.Run("DPoPRequired with Bearer scheme and DPoP proof but no cnf - error", func(t *testing.T) {
		// RFC 9449 Section 7.2: Bearer scheme + DPoP proof = invalid_request
		// This applies regardless of whether token has cnf claim
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: false, // No cnf claim
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
			WithDPoPMode(DPoPRequired),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"token",
			AuthSchemeBearer, // Bearer scheme
			"dpop-proof",     // DPoP proof present
			"POST",
			"https://example.com",
		)

		// Must reject: Bearer scheme not supported in Required mode
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidRequest)
		// Per RFC 6750 Section 3.1: unsupported authentication method returns NO error_description
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			assert.Empty(t, validationErr.Message, "error_description should be empty per RFC 6750 Section 3.1")
		}
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)
	})

	t.Run("ATH validation success", func(t *testing.T) {
		// Test that ATH (access token hash) is validated when present
		accessToken := "test-access-token"
		expectedATH := computeAccessTokenHash(accessToken)

		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 expectedATH, // Correct ATH
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			accessToken,
			AuthSchemeDPoP,
			"dpop-proof",
			"POST",
			"https://example.com/api",
		)

		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.NotNil(t, dpopCtx)
	})

	t.Run("ATH validation failure - mismatch", func(t *testing.T) {
		// Test that ATH mismatch is rejected
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 "wrong-ath-value", // Wrong ATH
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"test-access-token",
			AuthSchemeDPoP,
			"dpop-proof",
			"POST",
			"https://example.com/api",
		)

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidDPoPProof)
		assert.Contains(t, err.Error(), "ath")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)
	})

	t.Run("ATH validation failure - empty ATH", func(t *testing.T) {
		// Test that empty ATH is rejected
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 "", // Empty ATH
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"test-access-token",
			AuthSchemeDPoP,
			"dpop-proof",
			"POST",
			"https://example.com/api",
		)

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidDPoPProof)
		assert.Contains(t, err.Error(), "must include ath")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			assert.Equal(t, ErrorCodeDPoPATHMismatch, validationErr.Code)
		}
	})

	t.Run("claims do not implement TokenClaims interface with DPoP scheme", func(t *testing.T) {
		// Test that non-TokenClaims type with DPoP scheme returns error early
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				// Return plain string instead of TokenClaims implementation
				return "plain-string-claims", nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 computeAccessTokenHash("test-access-token"),
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"test-access-token",
			AuthSchemeDPoP,
			"dpop-proof",
			"POST",
			"https://example.com/api",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "Token claims do not support DPoP confirmation")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			assert.Equal(t, ErrorCodeConfigInvalid, validationErr.Code)
		}
	})

	t.Run("claims do not implement TokenClaims interface with Unknown scheme and DPoP proof", func(t *testing.T) {
		// Test defensive check in validateDPoPToken for Unknown scheme with DPoP proof
		// This tests the !supportsConfirmation check inside validateDPoPToken itself
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				// Return plain string instead of TokenClaims implementation
				return "plain-string-claims", nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 computeAccessTokenHash("test-access-token"),
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		// Use Unknown scheme (not DPoP or Bearer) to bypass early checks
		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"test-access-token",
			AuthSchemeUnknown, // Unknown scheme bypasses the early check at line 234
			"dpop-proof",
			"POST",
			"https://example.com/api",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "Token claims do not support DPoP confirmation")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			assert.Equal(t, ErrorCodeConfigInvalid, validationErr.Code)
		}
	})

	t.Run("claims implement TokenClaims but no cnf claim with Unknown scheme and DPoP proof", func(t *testing.T) {
		// Test defensive check for !hasConfirmationClaim inside validateDPoPToken (line 338)
		// This is reached when authScheme is Unknown with DPoP proof but token has no cnf claim
		tokenValidator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				// Return TokenClaims implementation but WITHOUT cnf claim
				return &mockTokenClaims{
					hasConfirmation: false, // No cnf claim
					jkt:             "",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 computeAccessTokenHash("test-access-token"),
				}, nil
			},
		}

		c, err := New(
			WithValidator(tokenValidator),
		)
		require.NoError(t, err)

		// Use Unknown scheme to bypass early cnf check at line 260
		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"test-access-token",
			AuthSchemeUnknown, // Unknown scheme bypasses early check
			"dpop-proof",
			"POST",
			"https://example.com/api",
		)

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDPoPBindingMismatch)
		assert.Contains(t, err.Error(), "Token must have cnf claim for DPoP binding")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			assert.Equal(t, ErrorCodeDPoPBindingMismatch, validationErr.Code)
		}
	})
}

// TestCheckTokenWithDPoP_LoggingPaths tests logging branches for better coverage
func TestCheckTokenWithDPoP_LoggingPaths(t *testing.T) {
	t.Run("successful validation with debug logging", func(t *testing.T) {
		accessToken := "token"
		expectedATH := computeAccessTokenHash(accessToken)
		logger := &mockLogger{}
		validator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 expectedATH,
				}, nil
			},
		}

		c, err := New(
			WithValidator(validator),
			WithLogger(logger),
			WithDPoPMode(DPoPAllowed),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			accessToken,
			AuthSchemeDPoP,
			"proof",
			"POST",
			"https://example.com/api",
		)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.NotNil(t, dpopCtx)

		// Verify debug logs for successful validation
		assert.NotEmpty(t, logger.debugCalls)
		foundTokenLog := false
		foundProofLog := false
		for _, call := range logger.debugCalls {
			if call.msg == "Access token validated successfully" {
				foundTokenLog = true
			}
			if call.msg == "DPoP proof validated successfully" {
				foundProofLog = true
			}
		}
		assert.True(t, foundTokenLog, "Expected debug log for token validation")
		assert.True(t, foundProofLog, "Expected debug log for DPoP proof validation")
	})

	t.Run("DPoP disabled with warning logging", func(t *testing.T) {
		logger := &mockLogger{}
		validator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: false,
				}, nil
			},
		}

		c, err := New(
			WithValidator(validator),
			WithLogger(logger),
			WithDPoPMode(DPoPDisabled),
		)
		require.NoError(t, err)

		// RFC 9449 Section 7.2: DPoP disabled = server unaware of DPoP
		// Should accept token and ignore DPoP header
		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"token",
			AuthSchemeBearer,             // Use Bearer scheme
			"proof-present-but-disabled", // DPoP proof present (but will be ignored)
			"POST",
			"https://example.com/api",
		)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Nil(t, dpopCtx)

		// Verify debug log for DPoP disabled mode
		assert.NotEmpty(t, logger.debugCalls)
		found := false
		for _, call := range logger.debugCalls {
			if call.msg == "DPoP header ignored (DPoP disabled, treating as Bearer-only)" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected debug log for DPoP disabled mode")
	})

	t.Run("JKT mismatch with error logging", func(t *testing.T) {
		accessToken := "token"
		expectedATH := computeAccessTokenHash(accessToken)
		logger := &mockLogger{}
		validator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "expected-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "different-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 expectedATH,
				}, nil
			},
		}

		c, err := New(
			WithValidator(validator),
			WithLogger(logger),
			WithDPoPMode(DPoPAllowed),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			accessToken,
			AuthSchemeDPoP,
			"proof",
			"POST",
			"https://example.com/api",
		)

		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		// Verify error log for JKT mismatch
		assert.NotEmpty(t, logger.errorCalls)
		found := false
		for _, call := range logger.errorCalls {
			if call.msg == "DPoP JKT mismatch" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected error log for JKT mismatch")
	})

	t.Run("HTM mismatch with error logging", func(t *testing.T) {
		accessToken := "token"
		expectedATH := computeAccessTokenHash(accessToken)
		logger := &mockLogger{}
		validator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "GET",
					htu:                 "https://example.com/api",
					iat:                 time.Now().Unix(),
					ath:                 expectedATH,
				}, nil
			},
		}

		c, err := New(
			WithValidator(validator),
			WithLogger(logger),
			WithDPoPMode(DPoPAllowed),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			accessToken,
			AuthSchemeDPoP,
			"proof",
			"POST", // Different from proof HTM
			"https://example.com/api",
		)

		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		// Verify error log for HTM mismatch
		assert.NotEmpty(t, logger.errorCalls)
		found := false
		for _, call := range logger.errorCalls {
			if call.msg == "DPoP HTM mismatch" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected error log for HTM mismatch")
	})

	t.Run("HTU mismatch with error logging", func(t *testing.T) {
		accessToken := "token"
		expectedATH := computeAccessTokenHash(accessToken)
		logger := &mockLogger{}
		validator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return &mockDPoPProofClaims{
					publicKeyThumbprint: "test-jkt",
					htm:                 "POST",
					htu:                 "https://example.com/wrong-url",
					iat:                 time.Now().Unix(),
					ath:                 expectedATH,
				}, nil
			},
		}

		c, err := New(
			WithValidator(validator),
			WithLogger(logger),
			WithDPoPMode(DPoPAllowed),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			accessToken,
			AuthSchemeDPoP,
			"proof",
			"POST",
			"https://example.com/api", // Different from proof HTU
		)

		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		// Verify error log for HTU mismatch
		assert.NotEmpty(t, logger.errorCalls)
		found := false
		for _, call := range logger.errorCalls {
			if call.msg == "DPoP HTU mismatch" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected error log for HTU mismatch")
	})

	t.Run("DPoP proof validation failure with error logging", func(t *testing.T) {
		logger := &mockLogger{}
		validator := &mockTokenValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return &mockTokenClaims{
					hasConfirmation: true,
					jkt:             "test-jkt",
				}, nil
			},
			dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
				return nil, errors.New("proof validation failed")
			},
		}

		c, err := New(
			WithValidator(validator),
			WithLogger(logger),
			WithDPoPMode(DPoPAllowed),
		)
		require.NoError(t, err)

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"token",
			AuthSchemeDPoP,
			"invalid-proof",
			"POST",
			"https://example.com/api",
		)

		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)

		// Verify error log for proof validation
		assert.NotEmpty(t, logger.errorCalls)
		found := false
		for _, call := range logger.errorCalls {
			if call.msg == "DPoP proof validation failed" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected error log for proof validation failure")
	})
}

// =============================================================================
// RFC 9449 Section 7.2 Compliance Tests
// =============================================================================

func TestCheckTokenWithDPoP_RFC9449_Section7_2_BearerWithDPoPProofRejected(t *testing.T) {
	// RFC 9449 Section 7.2: "When a resource server receives a request with both a DPoP proof
	// and an access token in the Authorization header using the Bearer scheme, the resource
	// server MUST reject the request."
	//
	// This test verifies that ANY Bearer token + DPoP proof combination is rejected,
	// regardless of whether the token has a cnf claim or not.

	tests := []struct {
		name            string
		tokenHasCnf     bool
		dpopMode        DPoPMode
		wantErrorCode   string
		wantErrorMsg    string
		wantSentinelErr error
	}{
		{
			name:            "Bearer + DPoP proof + non-DPoP token (DPoP Allowed)",
			tokenHasCnf:     false,
			dpopMode:        DPoPAllowed,
			wantErrorCode:   ErrorCodeInvalidRequest,
			wantErrorMsg:    "Bearer scheme cannot be used when DPoP proof is present",
			wantSentinelErr: ErrInvalidRequest,
		},
		{
			name:            "Bearer + DPoP proof + DPoP-bound token (DPoP Allowed)",
			tokenHasCnf:     true,
			dpopMode:        DPoPAllowed,
			wantErrorCode:   ErrorCodeInvalidToken,
			wantErrorMsg:    "DPoP-bound token requires the DPoP authentication scheme",
			wantSentinelErr: ErrJWTInvalid,
		},
		{
			name:            "Bearer + DPoP proof + non-DPoP token (DPoP Required)",
			tokenHasCnf:     false,
			dpopMode:        DPoPRequired,
			wantErrorCode:   ErrorCodeInvalidRequest,
			wantErrorMsg:    "", // Empty per RFC 6750 Section 3.1 for unsupported authentication method
			wantSentinelErr: ErrInvalidRequest,
		},
		{
			name:            "Bearer + DPoP proof + DPoP-bound token (DPoP Required)",
			tokenHasCnf:     true,
			dpopMode:        DPoPRequired,
			wantErrorCode:   ErrorCodeInvalidRequest,
			wantErrorMsg:    "", // Empty per RFC 6750 Section 3.1 for unsupported authentication method
			wantSentinelErr: ErrInvalidRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedJKT := "test-jkt"
			accessToken := "test-access-token"
			expectedATH := computeAccessTokenHash(accessToken)

			tokenValidator := &mockTokenValidator{
				validateFunc: func(ctx context.Context, token string) (any, error) {
					return &mockTokenClaims{
						hasConfirmation: tt.tokenHasCnf,
						jkt:             expectedJKT,
					}, nil
				},
				dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
					return &mockDPoPProofClaims{
						jti:                 "unique-jti",
						htm:                 "GET",
						htu:                 "https://api.example.com/resource",
						iat:                 time.Now().Unix(),
						publicKeyThumbprint: expectedJKT,
						ath:                 expectedATH,
					}, nil
				},
			}

			c, err := New(
				WithValidator(tokenValidator),
				WithDPoPMode(tt.dpopMode),
			)
			require.NoError(t, err)

			// Make request with Bearer scheme + DPoP proof (RFC violation)
			claims, dpopCtx, err := c.CheckTokenWithDPoP(
				context.Background(),
				accessToken,
				AuthSchemeBearer, // Bearer scheme
				"dpop-proof",     // DPoP proof present
				"GET",
				"https://api.example.com/resource",
			)

			// Must be rejected per RFC 9449 Section 7.2
			assert.Error(t, err)
			assert.Nil(t, claims)
			assert.Nil(t, dpopCtx)
			if tt.wantErrorMsg != "" {
				assert.Contains(t, err.Error(), tt.wantErrorMsg)
			}
			assert.ErrorIs(t, err, tt.wantSentinelErr)

			var validationErr *ValidationError
			if errors.As(err, &validationErr) {
				assert.Equal(t, tt.wantErrorCode, validationErr.Code)
				// For Required mode with empty wantErrorMsg, verify error_description is empty
				if tt.dpopMode == DPoPRequired && tt.wantErrorMsg == "" {
					assert.Empty(t, validationErr.Message, "error_description should be empty per RFC 6750 Section 3.1")
				}
			}
		})
	}
}

// =============================================================================
// RFC 9449 Section 7.1 Compliance Tests
// =============================================================================

func TestCheckTokenWithDPoP_RFC9449_Section7_1_DPoPSchemeRequiresCnfClaim(t *testing.T) {
	// RFC 9449 Section 7.1: DPoP scheme MUST only be used with DPoP-bound tokens.
	// A token is DPoP-bound if it contains the cnf (confirmation) claim with jkt member.
	//
	// This test verifies that using DPoP authorization scheme with a non-DPoP-bound token
	// (one without cnf claim) is rejected.

	tests := []struct {
		name          string
		dpopMode      DPoPMode
		wantErrorCode string
		wantErrorMsg  string
	}{
		{
			name:          "DPoP scheme without cnf claim (DPoP Allowed)",
			dpopMode:      DPoPAllowed,
			wantErrorCode: ErrorCodeInvalidToken,
			wantErrorMsg:  "DPoP scheme requires a DPoP-bound access token",
		},
		{
			name:          "DPoP scheme without cnf claim (DPoP Required)",
			dpopMode:      DPoPRequired,
			wantErrorCode: ErrorCodeInvalidToken,
			wantErrorMsg:  "DPoP scheme requires a DPoP-bound access token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedJKT := "test-jkt"
			accessToken := "test-access-token"
			expectedATH := computeAccessTokenHash(accessToken)

			tokenValidator := &mockTokenValidator{
				validateFunc: func(ctx context.Context, token string) (any, error) {
					// Token WITHOUT cnf claim
					return &mockTokenClaims{
						hasConfirmation: false,
						jkt:             "",
					}, nil
				},
				dpopValidateFunc: func(ctx context.Context, proof string) (DPoPProofClaims, error) {
					return &mockDPoPProofClaims{
						jti:                 "unique-jti",
						htm:                 "GET",
						htu:                 "https://api.example.com/resource",
						iat:                 time.Now().Unix(),
						publicKeyThumbprint: expectedJKT,
						ath:                 expectedATH,
					}, nil
				},
			}

			c, err := New(
				WithValidator(tokenValidator),
				WithDPoPMode(tt.dpopMode),
			)
			require.NoError(t, err)

			// Make request with DPoP scheme but non-DPoP-bound token
			claims, dpopCtx, err := c.CheckTokenWithDPoP(
				context.Background(),
				accessToken,
				AuthSchemeDPoP, // DPoP scheme
				"dpop-proof",
				"GET",
				"https://api.example.com/resource",
			)

			// Must be rejected - DPoP scheme requires DPoP-bound token (with cnf claim)
			assert.Error(t, err)
			assert.Nil(t, claims)
			assert.Nil(t, dpopCtx)
			assert.Contains(t, err.Error(), tt.wantErrorMsg)
			assert.ErrorIs(t, err, ErrInvalidToken)

			var validationErr *ValidationError
			if errors.As(err, &validationErr) {
				assert.Equal(t, tt.wantErrorCode, validationErr.Code)
			}
		})
	}
}
