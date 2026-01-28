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

func TestDefaultErrorHandler_MessageBasedMapping_Issuer(t *testing.T) {
	// Test fallback message-based mapping for issuer errors
	validationErr := core.NewValidationError("custom_code", "something about issuer", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestDefaultErrorHandler_MessageBasedMapping_Audience(t *testing.T) {
	// Test fallback message-based mapping for audience errors
	validationErr := core.NewValidationError("custom_code", "something about audience", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestDefaultErrorHandler_MessageBasedMapping_Expired(t *testing.T) {
	// Test fallback message-based mapping for expired errors
	validationErr := core.NewValidationError("custom_code", "something expired", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
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

func TestDefaultErrorHandler_MessageBasedMapping_JWKS(t *testing.T) {
	// Test fallback message-based mapping for JWKS errors
	validationErr := core.NewValidationError("custom_code", "failed to fetch JWKS from server", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "unable to verify token", st.Message())
}

func TestDefaultErrorHandler_MessageBasedMapping_JWKSLowercase(t *testing.T) {
	// Test fallback message-based mapping for jwks (lowercase)
	validationErr := core.NewValidationError("custom_code", "error fetching jwks", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "unable to verify token", st.Message())
}

func TestDefaultErrorHandler_MessageBasedMapping_KeySet(t *testing.T) {
	// Test fallback message-based mapping for key set errors
	validationErr := core.NewValidationError("custom_code", "error with key set", nil)
	err := DefaultErrorHandler(validationErr)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "unable to verify token", st.Message())
}

