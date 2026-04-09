package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNew_InvalidConfiguration(t *testing.T) {
	t.Run("missing validator", func(t *testing.T) {
		_, err := New()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrValidatorNil)
	})

	t.Run("nil validator option", func(t *testing.T) {
		_, err := New(WithValidator(nil))
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrValidatorNil)
	})

	t.Run("nil logger option", func(t *testing.T) {
		jwtValidator := createTestValidator(t)
		_, err := New(
			WithValidator(jwtValidator),
			WithLogger(nil),
		)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrLoggerNil)
	})

	t.Run("nil token extractor option", func(t *testing.T) {
		jwtValidator := createTestValidator(t)
		_, err := New(
			WithValidator(jwtValidator),
			WithTokenExtractor(nil),
		)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenExtractorNil)
	})

	t.Run("nil error handler option", func(t *testing.T) {
		jwtValidator := createTestValidator(t)
		_, err := New(
			WithValidator(jwtValidator),
			WithErrorHandler(nil),
		)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrErrorHandlerNil)
	})
}

func TestOptions(t *testing.T) {
	jwtValidator := createTestValidator(t)

	t.Run("WithCredentialsOptional", func(t *testing.T) {
		interceptor, err := New(
			WithValidator(jwtValidator),
			WithCredentialsOptional(true),
		)
		require.NoError(t, err)
		assert.NotNil(t, interceptor)
	})

	t.Run("WithLogger", func(t *testing.T) {
		logger := &mockLogger{}
		interceptor, err := New(
			WithValidator(jwtValidator),
			WithLogger(logger),
		)
		require.NoError(t, err)
		assert.NotNil(t, interceptor)
	})

	t.Run("WithTokenExtractor", func(t *testing.T) {
		customExtractor := func(ctx context.Context) (string, error) {
			return "custom-token", nil
		}
		interceptor, err := New(
			WithValidator(jwtValidator),
			WithTokenExtractor(customExtractor),
		)
		require.NoError(t, err)
		assert.NotNil(t, interceptor)
	})

	t.Run("WithErrorHandler", func(t *testing.T) {
		customHandler := func(err error) error {
			return status.Error(codes.Internal, "custom error")
		}
		interceptor, err := New(
			WithValidator(jwtValidator),
			WithErrorHandler(customHandler),
		)
		require.NoError(t, err)
		assert.NotNil(t, interceptor)
	})

	t.Run("WithExcludedMethods", func(t *testing.T) {
		interceptor, err := New(
			WithValidator(jwtValidator),
			WithExcludedMethods("/health.Check", "/grpc.health.v1.Health/Check"),
		)
		require.NoError(t, err)
		assert.NotNil(t, interceptor)
	})
}
