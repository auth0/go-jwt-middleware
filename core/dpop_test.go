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
}

func (m *mockDPoPProofClaims) GetJTI() string                 { return m.jti }
func (m *mockDPoPProofClaims) GetHTM() string                 { return m.htm }
func (m *mockDPoPProofClaims) GetHTU() string                 { return m.htu }
func (m *mockDPoPProofClaims) GetIAT() int64                  { return m.iat }
func (m *mockDPoPProofClaims) GetPublicKeyThumbprint() string { return m.publicKeyThumbprint }
func (m *mockDPoPProofClaims) GetPublicKey() any              { return m.publicKey }

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
		"", // No DPoP proof provided
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.ErrorIs(t, err, ErrInvalidDPoPProof)
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
		"", // No DPoP proof
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.ErrorIs(t, err, ErrBearerNotAllowed)
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
	futureIAT := time.Now().Unix() + 10 // 10 seconds in future (default leeway is 5s)

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

	// Even with DPoP proof and cnf claim, should be treated as Bearer
	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		"dpop-proof", // Proof is ignored
		"GET",
		"https://api.example.com/resource",
	)

	// Should fail because token has cnf but no proof validation
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	assert.ErrorIs(t, err, ErrInvalidDPoPProof)
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
		"", // No proof
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.errorCalls)
	assert.Equal(t, "Token has cnf claim but no DPoP proof provided", logger.errorCalls[0].msg)
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
		"",
		"",
		"",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.errorCalls)
	assert.Equal(t, "Bearer token provided but DPoP is required", logger.errorCalls[0].msg)
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

	claims, dpopCtx, err := c.CheckTokenWithDPoP(
		context.Background(),
		"dpop-bound-token",
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.warnCalls)
	assert.Equal(t, "DPoP header present but DPoP is disabled, treating as Bearer token", logger.warnCalls[0].msg)
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
		"dpop-proof",
		"GET",
		"https://api.example.com/resource",
	)

	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Nil(t, dpopCtx)
	require.NotEmpty(t, logger.errorCalls)
	assert.Equal(t, "DPoP proof provided but token has no cnf claim", logger.errorCalls[0].msg)
}

func TestCheckTokenWithDPoP_WithLogger_JKTMismatch(t *testing.T) {
	now := time.Now().Unix()
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
			"",
			"POST",
			"https://example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "DPoP proof is required")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)
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
			"", // No DPoP proof
			"POST",
			"https://example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "DPoP proof is required")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)
	})

	t.Run("thumbprint mismatch - error", func(t *testing.T) {
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
			"proof",
			"POST",
			"https://example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
		assert.Nil(t, claims)
		assert.Nil(t, dpopCtx)
	})
}

// TestCheckTokenWithDPoP_LoggingPaths tests logging branches for better coverage
func TestCheckTokenWithDPoP_LoggingPaths(t *testing.T) {
	t.Run("successful validation with debug logging", func(t *testing.T) {
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
			"token",
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

		claims, dpopCtx, err := c.CheckTokenWithDPoP(
			context.Background(),
			"token",
			"proof-present-but-disabled", // DPoP proof present
			"POST",
			"https://example.com/api",
		)

		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Nil(t, dpopCtx)

		// Verify warning log
		assert.NotEmpty(t, logger.warnCalls)
		found := false
		for _, call := range logger.warnCalls {
			if call.msg == "DPoP header present but DPoP is disabled, treating as Bearer token" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected warning log for DPoP disabled")
	})

	t.Run("JKT mismatch with error logging", func(t *testing.T) {
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
			"token",
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
			"token",
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
			"token",
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
