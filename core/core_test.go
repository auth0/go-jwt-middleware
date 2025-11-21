package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockValidator is a mock implementation of TokenValidator for testing.
type mockValidator struct {
	validateFunc func(ctx context.Context, token string) (any, error)
}

func (m *mockValidator) ValidateToken(ctx context.Context, token string) (any, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, errors.New("not implemented")
}

// mockLogger is a mock implementation of Logger for testing.
type mockLogger struct {
	debugCalls []logCall
	infoCalls  []logCall
	warnCalls  []logCall
	errorCalls []logCall
}

type logCall struct {
	msg  string
	args []any
}

func (m *mockLogger) Debug(msg string, args ...any) {
	m.debugCalls = append(m.debugCalls, logCall{msg, args})
}

func (m *mockLogger) Info(msg string, args ...any) {
	m.infoCalls = append(m.infoCalls, logCall{msg, args})
}

func (m *mockLogger) Warn(msg string, args ...any) {
	m.warnCalls = append(m.warnCalls, logCall{msg, args})
}

func (m *mockLogger) Error(msg string, args ...any) {
	m.errorCalls = append(m.errorCalls, logCall{msg, args})
}

func TestNew(t *testing.T) {
	validator := &mockValidator{
		validateFunc: func(ctx context.Context, token string) (any, error) {
			return "claims", nil
		},
	}

	t.Run("successful creation with required options", func(t *testing.T) {
		core, err := New(WithValidator(validator))
		require.NoError(t, err)
		assert.NotNil(t, core)
		assert.False(t, core.credentialsOptional) // Default is false
	})

	t.Run("successful creation with all options", func(t *testing.T) {
		logger := &mockLogger{}
		core, err := New(
			WithValidator(validator),
			WithCredentialsOptional(true),
			WithLogger(logger),
		)
		require.NoError(t, err)
		assert.NotNil(t, core)
		assert.True(t, core.credentialsOptional)
		assert.NotNil(t, core.logger)
	})

	t.Run("error when validator is missing", func(t *testing.T) {
		core, err := New()
		assert.Error(t, err)
		assert.Nil(t, core)
		assert.Contains(t, err.Error(), "validator is required")
	})

	t.Run("error when validator is nil", func(t *testing.T) {
		core, err := New(WithValidator(nil))
		assert.Error(t, err)
		assert.Nil(t, core)
		assert.Contains(t, err.Error(), "validator cannot be nil")
	})

	t.Run("error when logger is nil", func(t *testing.T) {
		core, err := New(
			WithValidator(validator),
			WithLogger(nil),
		)
		assert.Error(t, err)
		assert.Nil(t, core)
		assert.Contains(t, err.Error(), "logger cannot be nil")
	})
}

func TestCore_CheckToken(t *testing.T) {
	t.Run("successful validation", func(t *testing.T) {
		expectedClaims := map[string]any{"sub": "user123"}
		validator := &mockValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return expectedClaims, nil
			},
		}

		core, err := New(WithValidator(validator))
		require.NoError(t, err)

		claims, err := core.CheckToken(context.Background(), "valid-token")
		assert.NoError(t, err)
		assert.Equal(t, expectedClaims, claims)
	})

	t.Run("validation error", func(t *testing.T) {
		expectedErr := errors.New("invalid signature")
		validator := &mockValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return nil, expectedErr
			},
		}

		core, err := New(WithValidator(validator))
		require.NoError(t, err)

		claims, err := core.CheckToken(context.Background(), "invalid-token")
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("empty token with credentials required", func(t *testing.T) {
		validator := &mockValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				t.Fatal("validator should not be called with empty token")
				return nil, nil
			},
		}

		core, err := New(
			WithValidator(validator),
			WithCredentialsOptional(false), // Explicit false
		)
		require.NoError(t, err)

		claims, err := core.CheckToken(context.Background(), "")
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Equal(t, ErrJWTMissing, err)
	})

	t.Run("empty token with credentials optional", func(t *testing.T) {
		validator := &mockValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				t.Fatal("validator should not be called with empty token")
				return nil, nil
			},
		}

		core, err := New(
			WithValidator(validator),
			WithCredentialsOptional(true),
		)
		require.NoError(t, err)

		claims, err := core.CheckToken(context.Background(), "")
		assert.NoError(t, err)
		assert.Nil(t, claims)
	})

	t.Run("logger integration on success", func(t *testing.T) {
		validator := &mockValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return "claims", nil
			},
		}
		logger := &mockLogger{}

		core, err := New(
			WithValidator(validator),
			WithLogger(logger),
		)
		require.NoError(t, err)

		_, err = core.CheckToken(context.Background(), "valid-token")
		assert.NoError(t, err)

		// Should log successful validation
		assert.Len(t, logger.debugCalls, 1)
		assert.Contains(t, logger.debugCalls[0].msg, "validated successfully")
	})

	t.Run("logger integration on error", func(t *testing.T) {
		validator := &mockValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return nil, errors.New("validation failed")
			},
		}
		logger := &mockLogger{}

		core, err := New(
			WithValidator(validator),
			WithLogger(logger),
		)
		require.NoError(t, err)

		_, err = core.CheckToken(context.Background(), "invalid-token")
		assert.Error(t, err)

		// Should log validation error
		assert.Len(t, logger.errorCalls, 1)
		assert.Contains(t, logger.errorCalls[0].msg, "validation failed")
	})

	t.Run("logger integration on missing token", func(t *testing.T) {
		validator := &mockValidator{}
		logger := &mockLogger{}

		core, err := New(
			WithValidator(validator),
			WithLogger(logger),
		)
		require.NoError(t, err)

		_, err = core.CheckToken(context.Background(), "")
		assert.Error(t, err)

		// Should log warning
		assert.Len(t, logger.warnCalls, 1)
		assert.Contains(t, logger.warnCalls[0].msg, "credentials are required")
	})

	t.Run("logger integration on optional credentials", func(t *testing.T) {
		validator := &mockValidator{}
		logger := &mockLogger{}

		core, err := New(
			WithValidator(validator),
			WithCredentialsOptional(true),
			WithLogger(logger),
		)
		require.NoError(t, err)

		_, err = core.CheckToken(context.Background(), "")
		assert.NoError(t, err)

		// Should log debug message
		assert.Len(t, logger.debugCalls, 1)
		assert.Contains(t, logger.debugCalls[0].msg, "credentials are optional")
	})
}

func TestCore_CheckToken_Context(t *testing.T) {
	t.Run("context is passed to validator", func(t *testing.T) {
		type ctxKey struct{}
		expectedValue := "test-value"
		ctx := context.WithValue(context.Background(), ctxKey{}, expectedValue)

		var receivedCtx context.Context
		validator := &mockValidator{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				receivedCtx = ctx
				return "claims", nil
			},
		}

		core, err := New(WithValidator(validator))
		require.NoError(t, err)

		_, err = core.CheckToken(ctx, "token")
		assert.NoError(t, err)

		// Verify context was passed through
		assert.Equal(t, expectedValue, receivedCtx.Value(ctxKey{}))
	})
}

func TestContextHelpers(t *testing.T) {
	t.Run("SetClaims and GetClaims", func(t *testing.T) {
		type testClaims struct {
			Sub string
			Aud string
		}

		claims := &testClaims{
			Sub: "user123",
			Aud: "api",
		}

		ctx := context.Background()
		ctx = SetClaims(ctx, claims)

		retrieved, err := GetClaims[*testClaims](ctx)
		assert.NoError(t, err)
		assert.Equal(t, claims, retrieved)
	})

	t.Run("GetClaims with wrong type", func(t *testing.T) {
		type wrongType struct{}

		ctx := context.Background()
		ctx = SetClaims(ctx, "string-claims")

		retrieved, err := GetClaims[*wrongType](ctx)
		assert.Error(t, err)
		assert.Nil(t, retrieved)
		assert.Contains(t, err.Error(), "type assertion failed")
	})

	t.Run("GetClaims from empty context", func(t *testing.T) {
		ctx := context.Background()

		claims, err := GetClaims[string](ctx)
		assert.Error(t, err)
		assert.Equal(t, "", claims)
		assert.Equal(t, ErrClaimsNotFound, err)
	})

	t.Run("HasClaims returns true when claims exist", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetClaims(ctx, "claims")

		assert.True(t, HasClaims(ctx))
	})

	t.Run("HasClaims returns false when claims don't exist", func(t *testing.T) {
		ctx := context.Background()

		assert.False(t, HasClaims(ctx))
	})
}

func TestValidationError(t *testing.T) {
	t.Run("error message with details", func(t *testing.T) {
		details := errors.New("signature invalid")
		err := NewValidationError(ErrorCodeInvalidSignature, "token signature verification failed", details)

		assert.Contains(t, err.Error(), "token signature verification failed")
		assert.Contains(t, err.Error(), "signature invalid")
	})

	t.Run("error message without details", func(t *testing.T) {
		err := NewValidationError(ErrorCodeTokenMissing, "token is missing", nil)

		assert.Equal(t, "token is missing", err.Error())
	})

	t.Run("Unwrap returns details", func(t *testing.T) {
		details := errors.New("underlying error")
		err := NewValidationError(ErrorCodeInvalidClaims, "validation failed", details)

		assert.Equal(t, details, errors.Unwrap(err))
	})

	t.Run("Is works with ErrJWTInvalid", func(t *testing.T) {
		err := NewValidationError(ErrorCodeInvalidSignature, "bad signature", nil)

		assert.True(t, errors.Is(err, ErrJWTInvalid))
	})
}
