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
// and RFC 6750/RFC 9449 compliant WWW-Authenticate headers.
//
// In DPoP allowed mode, both Bearer and DPoP challenges are returned per RFC 9449 Section 6.1.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	// Get auth context from request using core functions
	authScheme := core.GetAuthScheme(r.Context())
	dpopMode := core.GetDPoPMode(r.Context())

	// Extract error details
	statusCode, errorResp, wwwAuthHeaders := mapErrorToResponse(err, authScheme, dpopMode)

	// Set headers
	w.Header().Set("Content-Type", "application/json")
	for _, header := range wwwAuthHeaders {
		w.Header().Add("WWW-Authenticate", header)
	}

	// Write response
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(errorResp)
}

// mapErrorToResponse maps errors to appropriate HTTP responses with WWW-Authenticate headers.
// In DPoP allowed mode, returns both Bearer and DPoP challenges per RFC 9449 Section 6.1.
func mapErrorToResponse(err error, authScheme AuthScheme, dpopMode core.DPoPMode) (statusCode int, resp ErrorResponse, wwwAuthHeaders []string) {
	// Check for JWT missing error
	// Per RFC 6750 Section 3.1, if the request lacks authentication information,
	// the server SHOULD NOT include error codes in the WWW-Authenticate header.
	if errors.Is(err, ErrJWTMissing) {
		headers := buildBareWWWAuthenticateHeaders(dpopMode)
		return http.StatusUnauthorized, ErrorResponse{
			Error: "invalid_token",
		}, headers
	}

	// Check for validation error with specific code
	var validationErr *core.ValidationError
	if errors.As(err, &validationErr) {
		return mapValidationError(validationErr, authScheme, dpopMode)
	}

	// Check for general JWT invalid error
	if errors.Is(err, ErrJWTInvalid) {
		headers := buildWWWAuthenticateHeaders(
			"invalid_token", "JWT is invalid",
			authScheme, dpopMode, true, // ambiguous case - error in both
		)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "JWT is invalid",
		}, headers
	}

	// Default to internal server error for unexpected errors
	return http.StatusInternalServerError, ErrorResponse{
		Error:            "server_error",
		ErrorDescription: "An internal error occurred while processing the request",
	}, nil
}

// mapValidationError maps core.ValidationError codes to HTTP responses with appropriate WWW-Authenticate headers.
func mapValidationError(err *core.ValidationError, authScheme AuthScheme, dpopMode core.DPoPMode) (statusCode int, resp ErrorResponse, wwwAuthHeaders []string) {
	// Map error codes to HTTP status codes and error types
	switch err.Code {
	// Token validation errors (Bearer-related, but apply to all tokens)
	case core.ErrorCodeTokenExpired:
		headers := buildWWWAuthenticateHeaders(
			"invalid_token", "The access token expired",
			authScheme, dpopMode, false, // Bearer error
		)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token expired",
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeTokenNotYetValid:
		headers := buildWWWAuthenticateHeaders(
			"invalid_token", "The access token is not yet valid",
			authScheme, dpopMode, false, // Bearer error
		)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token is not yet valid",
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeInvalidSignature:
		headers := buildWWWAuthenticateHeaders(
			"invalid_token", "The access token signature is invalid",
			authScheme, dpopMode, false, // Bearer error
		)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token signature is invalid",
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeTokenMalformed:
		headers := buildWWWAuthenticateHeaders(
			"invalid_request", "The access token is malformed",
			authScheme, dpopMode, false, // Bearer error
		)
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "The access token is malformed",
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeInvalidIssuer:
		headers := buildWWWAuthenticateHeaders(
			"insufficient_scope", "The access token was issued by an untrusted issuer",
			authScheme, dpopMode, false, // Bearer error
		)
		return http.StatusForbidden, ErrorResponse{
			Error:            "insufficient_scope",
			ErrorDescription: "The access token was issued by an untrusted issuer",
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeInvalidAudience:
		headers := buildWWWAuthenticateHeaders(
			"insufficient_scope", "The access token audience does not match",
			authScheme, dpopMode, false, // Bearer error
		)
		return http.StatusForbidden, ErrorResponse{
			Error:            "insufficient_scope",
			ErrorDescription: "The access token audience does not match",
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeInvalidAlgorithm:
		headers := buildWWWAuthenticateHeaders(
			"invalid_token", "The access token uses an unsupported algorithm",
			authScheme, dpopMode, false, // Bearer error
		)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token uses an unsupported algorithm",
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeJWKSFetchFailed, core.ErrorCodeJWKSKeyNotFound:
		headers := buildWWWAuthenticateHeaders(
			"invalid_token", "Unable to verify the access token",
			authScheme, dpopMode, false, // Bearer error
		)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "Unable to verify the access token",
			ErrorCode:        err.Code,
		}, headers

	// DPoP-specific error codes
	case core.ErrorCodeDPoPProofInvalid, core.ErrorCodeDPoPProofMissing,
		core.ErrorCodeDPoPHTMMismatch, core.ErrorCodeDPoPHTUMismatch, core.ErrorCodeDPoPATHMismatch,
		core.ErrorCodeDPoPProofExpired, core.ErrorCodeDPoPProofTooNew:
		headers := buildDPoPWWWAuthenticateHeaders("invalid_dpop_proof", err.Message, dpopMode)
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_dpop_proof",
			ErrorDescription: err.Message,
			ErrorCode:        err.Code,
		}, headers

	// DPoP binding mismatch is treated as invalid_token
	case core.ErrorCodeDPoPBindingMismatch:
		headers := buildDPoPWWWAuthenticateHeaders("invalid_token", err.Message, dpopMode)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: err.Message,
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeBearerNotAllowed:
		headers := []string{
			fmt.Sprintf(`DPoP algs="%s", error="invalid_request", error_description="Bearer tokens are not allowed (DPoP required)"`, validator.DPoPSupportedAlgorithms),
		}
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Bearer tokens are not allowed (DPoP required)",
			ErrorCode:        err.Code,
		}, headers

	case core.ErrorCodeDPoPNotAllowed:
		headers := []string{
			`Bearer realm="api", error="invalid_request", error_description="DPoP tokens are not allowed (Bearer only)"`,
		}
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "DPoP tokens are not allowed (Bearer only)",
			ErrorCode:        err.Code,
		}, headers

	// RFC 6750 Section 3.1: invalid_request is 400 Bad Request
	// This includes:
	// - RFC 9449 Section 7.2: Bearer + DPoP proof (multiple authentication mechanisms)
	// - Malformed Authorization header
	// - Missing required parameters
	// - Otherwise malformed requests
	case core.ErrorCodeInvalidRequest:
		headers := buildWWWAuthenticateHeaders(
			"invalid_request", err.Message,
			authScheme, dpopMode, true, // error in both Bearer and DPoP challenges
		)
		return http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Message,
			ErrorCode:        err.Code,
		}, headers

	// RFC 9449 Section 7.1: DPoP scheme without cnf claim = invalid_token
	case core.ErrorCodeInvalidToken:
		headers := buildWWWAuthenticateHeaders(
			"invalid_token", err.Message,
			authScheme, dpopMode, false,
		)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: err.Message,
			ErrorCode:        err.Code,
		}, headers

	default:
		// Generic invalid token error
		headers := buildWWWAuthenticateHeaders(
			"invalid_token", "The access token is invalid",
			authScheme, dpopMode, true, // ambiguous
		)
		return http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "The access token is invalid",
			ErrorCode:        err.Code,
		}, headers
	}
}

// buildWWWAuthenticateHeaders builds appropriate WWW-Authenticate headers based on auth scheme and DPoP mode.
// Returns both Bearer and DPoP challenges in allowed mode per RFC 9449 Section 6.1.
func buildWWWAuthenticateHeaders(errorCode, errorDesc string, authScheme AuthScheme, dpopMode core.DPoPMode, errorInBoth bool) []string {
	switch dpopMode {
	case core.DPoPRequired:
		// Only DPoP challenge in required mode
		return []string{
			fmt.Sprintf(`DPoP algs="%s", error="%s", error_description="%s"`, validator.DPoPSupportedAlgorithms, errorCode, errorDesc),
		}
	case core.DPoPDisabled:
		// Only Bearer challenge in disabled mode
		return []string{
			fmt.Sprintf(`Bearer realm="api", error="%s", error_description="%s"`, errorCode, errorDesc),
		}
	case core.DPoPAllowed:
		// Both Bearer and DPoP challenges in allowed mode
		// Error details go in the challenge matching the scheme used, or both if ambiguous
		var headers []string
		if authScheme == AuthSchemeBearer || authScheme == AuthSchemeUnknown || errorInBoth {
			headers = append(headers, fmt.Sprintf(`Bearer realm="api", error="%s", error_description="%s"`, errorCode, errorDesc))
		} else {
			headers = append(headers, `Bearer realm="api"`)
		}
		if authScheme == AuthSchemeDPoP || authScheme == AuthSchemeUnknown || errorInBoth {
			headers = append(headers, fmt.Sprintf(`DPoP algs="%s", error="%s", error_description="%s"`, validator.DPoPSupportedAlgorithms, errorCode, errorDesc))
		} else {
			headers = append(headers, fmt.Sprintf(`DPoP algs="%s"`, validator.DPoPSupportedAlgorithms))
		}
		return headers
	default:
		// Fallback to Bearer only
		return []string{
			fmt.Sprintf(`Bearer realm="api", error="%s", error_description="%s"`, errorCode, errorDesc),
		}
	}
}

// buildDPoPWWWAuthenticateHeaders builds WWW-Authenticate headers for DPoP-specific errors.
func buildDPoPWWWAuthenticateHeaders(errorCode, errorDesc string, dpopMode core.DPoPMode) []string {
	switch dpopMode {
	case core.DPoPRequired:
		// Only DPoP challenge with error
		return []string{
			fmt.Sprintf(`DPoP algs="%s", error="%s", error_description="%s"`, validator.DPoPSupportedAlgorithms, errorCode, errorDesc),
		}
	case core.DPoPDisabled:
		// This shouldn't happen (DPoP error when DPoP is disabled), but return Bearer fallback
		return []string{
			fmt.Sprintf(`Bearer realm="api", error="%s", error_description="%s"`, errorCode, errorDesc),
		}
	case core.DPoPAllowed:
		// Both challenges, error in DPoP only (since this is a DPoP-specific error)
		return []string{
			`Bearer realm="api"`,
			fmt.Sprintf(`DPoP algs="%s", error="%s", error_description="%s"`, validator.DPoPSupportedAlgorithms, errorCode, errorDesc),
		}
	default:
		// Fallback
		return []string{
			fmt.Sprintf(`DPoP algs="%s", error="%s", error_description="%s"`, validator.DPoPSupportedAlgorithms, errorCode, errorDesc),
		}
	}
}

// buildBareWWWAuthenticateHeaders builds bare WWW-Authenticate headers without error codes.
// Per RFC 6750 Section 3.1, when a request lacks authentication information, the server
// SHOULD NOT include error codes or error descriptions in the WWW-Authenticate header.
func buildBareWWWAuthenticateHeaders(dpopMode core.DPoPMode) []string {
	switch dpopMode {
	case core.DPoPRequired:
		// Only DPoP challenge in required mode
		return []string{
			fmt.Sprintf(`DPoP algs="%s"`, validator.DPoPSupportedAlgorithms),
		}
	case core.DPoPDisabled:
		// Only Bearer challenge in disabled mode
		return []string{
			`Bearer realm="api"`,
		}
	case core.DPoPAllowed:
		// Both challenges in allowed mode
		return []string{
			`Bearer realm="api"`,
			fmt.Sprintf(`DPoP algs="%s"`, validator.DPoPSupportedAlgorithms),
		}
	default:
		// Fallback to Bearer
		return []string{
			`Bearer realm="api"`,
		}
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
