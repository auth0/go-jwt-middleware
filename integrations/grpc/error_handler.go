package grpc

import (
	"errors"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorHandler converts validation errors to gRPC status errors.
type ErrorHandler func(error) error

// DefaultErrorHandler maps JWT validation errors to appropriate gRPC status codes.
// It returns gRPC status errors that follow standard gRPC error handling conventions.
//
// Error mapping:
//   - Token missing/expired/invalid signature → Unauthenticated
//   - Invalid issuer/audience → PermissionDenied
//   - Extractor errors (malformed header) → InvalidArgument
//   - JWKS/infrastructure errors → Internal
//   - Unknown errors → Unauthenticated (secure default)
func DefaultErrorHandler(err error) error {
	if err == nil {
		return nil
	}

	// Handle core validation errors (preferred path - uses error codes)
	var validationErr *core.ValidationError
	if errors.As(err, &validationErr) {
		return mapValidationError(validationErr)
	}

	// Handle specific sentinel errors
	if errors.Is(err, core.ErrJWTMissing) {
		return status.Error(codes.Unauthenticated, "missing credentials")
	}

	// Handle extractor errors
	if errors.Is(err, ErrMultipleAuthHeaders) ||
		errors.Is(err, ErrInvalidAuthFormat) ||
		errors.Is(err, ErrUnsupportedScheme) {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	// Default: treat unknown validation errors as Unauthenticated for security.
	// This ensures token validation failures don't leak as internal errors.
	// Note: JWKS errors should come through as ValidationError with appropriate codes.
	return status.Error(codes.Unauthenticated, "invalid or malformed token")
}

// mapValidationError maps core.ValidationError to gRPC status codes.
// This function relies on error codes from core package for reliable error classification.
func mapValidationError(err *core.ValidationError) error {
	switch err.Code {
	case core.ErrorCodeTokenMissing:
		return status.Error(codes.Unauthenticated, "missing credentials")
	case core.ErrorCodeTokenExpired:
		return status.Error(codes.Unauthenticated, "token expired")
	case core.ErrorCodeTokenNotYetValid:
		return status.Error(codes.Unauthenticated, "token not yet valid")
	case core.ErrorCodeInvalidIssuer:
		return status.Error(codes.PermissionDenied, "invalid issuer")
	case core.ErrorCodeInvalidAudience:
		return status.Error(codes.PermissionDenied, "invalid audience")
	case core.ErrorCodeInvalidSignature:
		return status.Error(codes.Unauthenticated, "invalid signature")
	case core.ErrorCodeTokenMalformed:
		return status.Error(codes.Unauthenticated, "malformed token")
	case core.ErrorCodeInvalidAlgorithm:
		return status.Error(codes.Unauthenticated, "invalid algorithm")
	case core.ErrorCodeJWKSFetchFailed, core.ErrorCodeJWKSKeyNotFound:
		// JWKS failures are server-side infrastructure errors
		return status.Error(codes.Internal, "unable to verify token")
	case core.ErrorCodeInvalidRequest:
		return status.Error(codes.InvalidArgument, err.Message)
	case core.ErrorCodeInvalidToken:
		return status.Error(codes.Unauthenticated, err.Message)
	case core.ErrorCodeInvalidClaims:
		return status.Error(codes.Unauthenticated, err.Message)
	case core.ErrorCodeConfigInvalid, core.ErrorCodeValidatorNotSet:
		// Configuration errors are server-side issues
		return status.Error(codes.Internal, "server configuration error")
	default:
		// Unknown error codes default to Unauthenticated for security.
		// If new error codes are added to core, they should be handled explicitly above.
		return status.Error(codes.Unauthenticated, err.Message)
	}
}
