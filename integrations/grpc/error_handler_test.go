package grpc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/auth0/go-jwt-middleware/v3/core"
)

func TestDefaultErrorHandler_JWTMissing(t *testing.T) {
	err := DefaultErrorHandler(core.ErrJWTMissing)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "missing credentials", st.Message())
}

func TestDefaultErrorHandler_TokenMissing(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeTokenMissing, "token is missing", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "missing credentials", st.Message())
}

func TestDefaultErrorHandler_TokenExpired(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeTokenExpired, "token has expired", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "token expired", st.Message())
}

func TestDefaultErrorHandler_TokenNotYetValid(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeTokenNotYetValid, "token not yet valid", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "token not yet valid", st.Message())
}

func TestDefaultErrorHandler_InvalidIssuer(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeInvalidIssuer, "invalid issuer", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Equal(t, "invalid issuer", st.Message())
}

func TestDefaultErrorHandler_InvalidAudience(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeInvalidAudience, "invalid audience", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Equal(t, "invalid audience", st.Message())
}

func TestDefaultErrorHandler_InvalidSignature(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeInvalidSignature, "invalid signature", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "invalid signature", st.Message())
}

func TestDefaultErrorHandler_TokenMalformed(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeTokenMalformed, "malformed token", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "malformed token", st.Message())
}

func TestDefaultErrorHandler_InvalidAlgorithm(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeInvalidAlgorithm, "invalid algorithm", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "invalid algorithm", st.Message())
}

func TestDefaultErrorHandler_JWKSFetchFailed(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeJWKSFetchFailed, "failed to fetch JWKS", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "unable to verify token", st.Message())
}

func TestDefaultErrorHandler_JWKSKeyNotFound(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeJWKSKeyNotFound, "key not found in JWKS", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "unable to verify token", st.Message())
}

func TestDefaultErrorHandler_InvalidRequest(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeInvalidRequest, "invalid request format", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Equal(t, "invalid request format", st.Message())
}

func TestDefaultErrorHandler_InvalidToken(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeInvalidToken, "invalid token", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "invalid token", st.Message())
}

func TestDefaultErrorHandler_GenericError(t *testing.T) {
	genericErr := errors.New("some other error")
	err := DefaultErrorHandler(genericErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "invalid or malformed token", st.Message())
}

func TestDefaultErrorHandler_NilError(t *testing.T) {
	err := DefaultErrorHandler(nil)
	assert.NoError(t, err)
}

func TestDefaultErrorHandler_UnknownErrorCode_DefaultsToUnauthenticated(t *testing.T) {
	// Unknown error codes default to Unauthenticated for security.
	// This ensures we don't accidentally leak information through error responses.
	// Note: We intentionally do NOT do string-based message matching as it's fragile.
	tests := []struct {
		name    string
		message string
	}{
		{"issuer in message", "something about issuer"},
		{"audience in message", "something about audience"},
		{"expired in message", "something expired"},
		{"generic message", "some unknown error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validationErr := core.NewValidationError("custom_unknown_code", tt.message, nil)
			err := DefaultErrorHandler(validationErr)

			st, ok := status.FromError(err)
			assert.True(t, ok)
			// All unknown codes should map to Unauthenticated as a secure default
			assert.Equal(t, codes.Unauthenticated, st.Code())
			// The message should be preserved from the ValidationError
			assert.Equal(t, tt.message, st.Message())
		})
	}
}

func TestDefaultErrorHandler_ExtractorError_InvalidFormat(t *testing.T) {
	grpcErr := DefaultErrorHandler(ErrInvalidAuthFormat)

	st, ok := status.FromError(grpcErr)
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDefaultErrorHandler_ExtractorError_MultipleHeaders(t *testing.T) {
	grpcErr := DefaultErrorHandler(ErrMultipleAuthHeaders)

	st, ok := status.FromError(grpcErr)
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDefaultErrorHandler_ExtractorError_UnsupportedScheme(t *testing.T) {
	grpcErr := DefaultErrorHandler(ErrUnsupportedScheme)

	st, ok := status.FromError(grpcErr)
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDefaultErrorHandler_JWKSErrors_UseErrorCodes(t *testing.T) {
	// JWKS errors should use proper error codes, not string-based matching.
	// This ensures reliable error handling regardless of message content.
	tests := []struct {
		name     string
		code     string
		message  string
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "JWKS fetch failed with proper code",
			code:     core.ErrorCodeJWKSFetchFailed,
			message:  "failed to fetch JWKS from server",
			wantCode: codes.Internal,
			wantMsg:  "unable to verify token",
		},
		{
			name:     "JWKS key not found with proper code",
			code:     core.ErrorCodeJWKSKeyNotFound,
			message:  "key not found in key set",
			wantCode: codes.Internal,
			wantMsg:  "unable to verify token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validationErr := core.NewValidationError(tt.code, tt.message, nil)
			err := DefaultErrorHandler(validationErr)

			st, ok := status.FromError(err)
			assert.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Equal(t, tt.wantMsg, st.Message())
		})
	}
}

func TestDefaultErrorHandler_ConfigErrors(t *testing.T) {
	// Configuration errors should map to Internal
	tests := []struct {
		name string
		code string
	}{
		{"config invalid", core.ErrorCodeConfigInvalid},
		{"validator not set", core.ErrorCodeValidatorNotSet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validationErr := core.NewValidationError(tt.code, "configuration error", nil)
			err := DefaultErrorHandler(validationErr)

			st, ok := status.FromError(err)
			assert.True(t, ok)
			assert.Equal(t, codes.Internal, st.Code())
			assert.Equal(t, "server configuration error", st.Message())
		})
	}
}

func TestDefaultErrorHandler_InvalidClaims(t *testing.T) {
	validationErr := core.NewValidationError(core.ErrorCodeInvalidClaims, "custom claims validation failed", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Equal(t, "custom claims validation failed", st.Message())
}

