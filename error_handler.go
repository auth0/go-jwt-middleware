package jwtmiddleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

var (
	// ErrJWTMissing is returned when the JWT is missing.
	// This is the same as core.ErrJWTMissing for consistency.
	ErrJWTMissing = core.ErrJWTMissing

	// ErrJWTInvalid is returned when the JWT is invalid.
	// This is the same as core.ErrJWTInvalid for consistency.
	ErrJWTInvalid = core.ErrJWTInvalid
)

// ErrorHandler is a handler which is called when an error occurs in the
// JWTMiddleware. The handler determines the HTTP response when a token is
// not found, is invalid, or other errors occur.
//
// The default handler (DefaultErrorHandler) provides:
//   - Structured JSON error responses with error codes
//   - RFC 6750 compliant WWW-Authenticate headers (Bearer tokens)
//   - Appropriate HTTP status codes based on error type
//   - Security-conscious error messages (no sensitive details by default)
//   - Extensible architecture for future authentication schemes (e.g., DPoP per RFC 9449)
//
// Custom error handlers should check for ErrJWTMissing and ErrJWTInvalid
// sentinel errors, as well as core.ValidationError for detailed error codes.
//
// Future extensions (e.g., DPoP support) can use the same pattern:
//   - Add DPoP-specific error codes to core.ValidationError
//   - Update mapValidationError to handle DPoP errors
//   - Return appropriate WWW-Authenticate headers with DPoP scheme
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// ErrorResponse represents a structured error response.
type ErrorResponse struct {
	// Error is the main error message
	Error string `json:"error"`

	// ErrorDescription provides additional context (optional)
	ErrorDescription string `json:"error_description,omitempty"`

	// ErrorCode is a machine-readable error code (optional)
	ErrorCode string `json:"error_code,omitempty"`
}

// DefaultErrorHandler is the default error handler implementation.
// It provides structured error responses with appropriate HTTP status codes
// and RFC 6750 compliant WWW-Authenticate headers.
func DefaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	// Extract error details
	statusCode, errorResp, wwwAuthenticate := mapErrorToResponse(err)

	// Set headers
	w.Header().Set("Content-Type", "application/json")
	if wwwAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", wwwAuthenticate)
	}

	// Write response
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(errorResp)
}

// mapErrorToResponse maps errors to appropriate HTTP responses
func mapErrorToResponse(err error) (statusCode int, resp ErrorResponse, wwwAuthenticate string) {
	// Check for JWT missing error
	if errors.Is(err, ErrJWTMissing) {
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "JWT is missing",
		}, `Bearer error="invalid_token", error_description="JWT is missing"`
	}

	// Check for validation error with specific code
	var validationErr *core.ValidationError
	if errors.As(err, &validationErr) {
		return mapValidationError(validationErr)
	}

	// Check for general JWT invalid error
	if errors.Is(err, ErrJWTInvalid) {
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "JWT is invalid",
		}, `Bearer error="invalid_token", error_description="JWT is invalid"`
	}

	// Default to internal server error for unexpected errors
	return http.StatusInternalServerError, ErrorResponse{
		Error:            "server_error",
		ErrorDescription: "An internal error occurred while processing the request",
	}, ""
}

// mapValidationError maps core.ValidationError codes to HTTP responses
// This function is extensible to support future authentication schemes like DPoP (RFC 9449)
func mapValidationError(err *core.ValidationError) (statusCode int, resp ErrorResponse, wwwAuthenticate string) {
	// Map error codes to HTTP status codes and RFC 6750 Bearer token error types
	// Future: Add DPoP-specific error codes and return appropriate DPoP challenge headers
	switch err.Code {
	case core.ErrorCodeTokenExpired:
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token expired",
			ErrorCode:        err.Code,
		}, `Bearer error="invalid_token", error_description="The access token expired"`

	case core.ErrorCodeTokenNotYetValid:
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token is not yet valid",
			ErrorCode:        err.Code,
		}, `Bearer error="invalid_token", error_description="The access token is not yet valid"`

	case core.ErrorCodeInvalidSignature:
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token signature is invalid",
			ErrorCode:        err.Code,
		}, `Bearer error="invalid_token", error_description="The access token signature is invalid"`

	case core.ErrorCodeTokenMalformed:
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The access token is malformed",
			ErrorCode:        err.Code,
		}, `Bearer error="invalid_request", error_description="The access token is malformed"`

	case core.ErrorCodeInvalidIssuer:
		return http.StatusForbidden, ErrorResponse{
			Error:            "insufficient_scope",
			ErrorDescription: "The access token was issued by an untrusted issuer",
			ErrorCode:        err.Code,
		}, `Bearer error="insufficient_scope", error_description="The access token was issued by an untrusted issuer"`

	case core.ErrorCodeInvalidAudience:
		return http.StatusForbidden, ErrorResponse{
			Error:            "insufficient_scope",
			ErrorDescription: "The access token audience does not match",
			ErrorCode:        err.Code,
		}, `Bearer error="insufficient_scope", error_description="The access token audience does not match"`

	case core.ErrorCodeInvalidAlgorithm:
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token uses an unsupported algorithm",
			ErrorCode:        err.Code,
		}, `Bearer error="invalid_token", error_description="The access token uses an unsupported algorithm"`

	case core.ErrorCodeJWKSFetchFailed, core.ErrorCodeJWKSKeyNotFound:
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "Unable to verify the access token",
			ErrorCode:        err.Code,
		}, `Bearer error="invalid_token", error_description="Unable to verify the access token"`

	// DPoP-specific error codes
	// All DPoP proof validation errors (missing, invalid, HTM/HTU mismatch, expired, future)
	// Per RFC 9449 Section 7.1, use "DPoP" scheme for DPoP-related errors with algs parameter
	case core.ErrorCodeDPoPProofInvalid, core.ErrorCodeDPoPProofMissing,
		core.ErrorCodeDPoPHTMMismatch, core.ErrorCodeDPoPHTUMismatch,
		core.ErrorCodeDPoPProofExpired, core.ErrorCodeDPoPProofTooNew:
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_dpop_proof",
			ErrorDescription: err.Message,
			ErrorCode:        err.Code,
		}, fmt.Sprintf(`DPoP algs="%s", error="invalid_dpop_proof", error_description="%s"`, validator.DPoPSupportedAlgorithms, err.Message)

	// DPoP binding mismatch is treated as invalid_token (token binding issue)
	case core.ErrorCodeDPoPBindingMismatch:
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: err.Message,
			ErrorCode:        err.Code,
		}, fmt.Sprintf(`DPoP algs="%s", error="invalid_token", error_description="%s"`, validator.DPoPSupportedAlgorithms, err.Message)

	case core.ErrorCodeBearerNotAllowed:
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Bearer tokens are not allowed (DPoP required)",
			ErrorCode:        err.Code,
		}, fmt.Sprintf(`DPoP algs="%s", error="invalid_request", error_description="Bearer tokens are not allowed (DPoP required)"`, validator.DPoPSupportedAlgorithms)

	case core.ErrorCodeDPoPNotAllowed:
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "DPoP tokens are not allowed (Bearer only)",
			ErrorCode:        err.Code,
		}, fmt.Sprintf(`DPoP algs="%s", error="invalid_request", error_description="DPoP tokens are not allowed (Bearer only)"`, validator.DPoPSupportedAlgorithms)

	default:
		// Generic invalid token error for other cases
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token is invalid",
			ErrorCode:        err.Code,
		}, `Bearer error="invalid_token", error_description="The access token is invalid"`
	}
}

// invalidError handles wrapping a JWT validation error with
// the concrete error ErrJWTInvalid. We do not expose this
// publicly because the interface methods of Is and Unwrap
// should give the user all they need.
type invalidError struct {
	details error
}

// Is allows the error to support equality to ErrJWTInvalid.
func (e invalidError) Is(target error) bool {
	return target == ErrJWTInvalid
}

// Error returns a string representation of the error.
func (e invalidError) Error() string {
	return fmt.Sprintf("%s: %s", ErrJWTInvalid, e.details)
}

// Unwrap allows the error to support equality to the
// underlying error and not just ErrJWTInvalid.
func (e invalidError) Unwrap() error {
	return e.details
}
