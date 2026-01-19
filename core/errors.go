package core

import "errors"

// Sentinel errors for JWT validation.
var (
	// ErrJWTMissing is returned when the JWT is missing from the request.
	ErrJWTMissing = errors.New("jwt missing")

	// ErrJWTInvalid is returned when the JWT is invalid.
	// This is typically wrapped with more specific validation errors.
	ErrJWTInvalid = errors.New("jwt invalid")

	// ErrInvalidToken is returned when the access token itself is invalid.
	// Used for token-level errors (e.g., DPoP scheme without cnf claim).
	ErrInvalidToken = errors.New("invalid access token")

	// ErrInvalidRequest is returned when the request format is invalid.
	// Used for protocol violations (e.g., Bearer + DPoP proof combination).
	ErrInvalidRequest = errors.New("invalid request")

	// ErrClaimsNotFound is returned when claims cannot be retrieved from context.
	ErrClaimsNotFound = errors.New("claims not found in context")
)

// ValidationError wraps JWT validation errors with additional context.
// It provides structured error information that can be used for
// logging, metrics, and returning appropriate error responses.
type ValidationError struct {
	// Code is a machine-readable error code (e.g., "token_expired", "invalid_signature")
	Code string

	// Message is a human-readable error message
	Message string

	// Details contains the underlying error
	Details error
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Details != nil {
		return e.Message + ": " + e.Details.Error()
	}
	return e.Message
}

// Unwrap returns the underlying error for error unwrapping.
func (e *ValidationError) Unwrap() error {
	return e.Details
}

// Is allows the error to be compared with ErrJWTInvalid.
func (e *ValidationError) Is(target error) bool {
	return target == ErrJWTInvalid
}

// Common error codes
const (
	ErrorCodeTokenMissing     = "token_missing" //nolint:gosec // False positive: this is not a credential
	ErrorCodeTokenMalformed   = "token_malformed"
	ErrorCodeTokenExpired     = "token_expired"
	ErrorCodeTokenNotYetValid = "token_not_yet_valid" //nolint:gosec // False positive: this is not a credential
	ErrorCodeInvalidSignature = "invalid_signature"
	ErrorCodeInvalidAlgorithm = "invalid_algorithm"
	ErrorCodeInvalidIssuer    = "invalid_issuer"
	ErrorCodeInvalidAudience  = "invalid_audience"
	ErrorCodeInvalidClaims    = "invalid_claims"
	ErrorCodeJWKSFetchFailed  = "jwks_fetch_failed"
	ErrorCodeJWKSKeyNotFound  = "jwks_key_not_found"
	ErrorCodeConfigInvalid    = "config_invalid"
	ErrorCodeValidatorNotSet  = "validator_not_set"
	ErrorCodeClaimsNotFound   = "claims_not_found"
	ErrorCodeInvalidToken     = "invalid_token"
	ErrorCodeInvalidRequest   = "invalid_request"
)

// NewValidationError creates a new ValidationError with the given code and message.
func NewValidationError(code, message string, details error) *ValidationError {
	return &ValidationError{
		Code:    code,
		Message: message,
		Details: details,
	}
}
