package jwtmiddleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Error types
var (
	// ErrJWTMissing is returned when the JWT is missing.
	ErrJWTMissing = errors.New("jwt missing")

	// ErrJWTInvalid is returned when the JWT is invalid.
	ErrJWTInvalid = errors.New("jwt invalid")

	// ErrMissingClaims is returned when no JWT claims are found in context.
	ErrMissingClaims = errors.New("no JWT claims found in context")

	// ErrInvalidClaims is returned when the JWT claims are invalid.
	ErrInvalidClaims = errors.New("invalid JWT claims type")
)

// JWTError represents a JWT-related error with structured information.
type JWTError struct {
	Type        error  // The error type (e.g., ErrJWTMissing, ErrJWTInvalid)
	Message     string // Human-readable message
	StatusCode  int    // HTTP status code
	Detail      string // Additional error details
	OriginalErr error  // Original wrapped error
}

// Error implements the error interface.
func (e *JWTError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Detail)
	}
	return e.Message
}

// Unwrap returns the wrapped error.
func (e *JWTError) Unwrap() error {
	return e.OriginalErr
}

// Is reports whether the target error matches this error.
func (e *JWTError) Is(target error) bool {
	return errors.Is(e.Type, target)
}

// NewJWTError creates a new JWTError with appropriate defaults based on the error type.
func NewJWTError(errType error, detail string, originalErr error) *JWTError {
	jwtErr := &JWTError{
		Type:        errType,
		OriginalErr: originalErr,
		Detail:      detail,
	}

	// Set default message and status code based on error type
	switch {
	case errors.Is(errType, ErrJWTMissing):
		jwtErr.Message = "JWT is missing"
		jwtErr.StatusCode = http.StatusBadRequest
	case errors.Is(errType, ErrJWTInvalid):
		jwtErr.Message = "JWT is invalid"
		jwtErr.StatusCode = http.StatusUnauthorized
	case errors.Is(errType, ErrMissingClaims):
		jwtErr.Message = "No JWT claims found in context"
		jwtErr.StatusCode = http.StatusInternalServerError
	case errors.Is(errType, ErrInvalidClaims):
		jwtErr.Message = "Invalid JWT claims type"
		jwtErr.StatusCode = http.StatusInternalServerError
	default:
		jwtErr.Message = "Something went wrong while checking the JWT"
		jwtErr.StatusCode = http.StatusInternalServerError
	}

	return jwtErr
}

// ErrorToJSON generates a consistent JSON-friendly map from a JWTError.
// This is used by error handlers across the middleware and framework adapters.
func ErrorToJSON(err error) map[string]string {
	result := map[string]string{}

	var jwtErr *JWTError
	if errors.As(err, &jwtErr) {
		// Use the structured error data
		result["message"] = jwtErr.Message
		if jwtErr.Detail != "" {
			result["detail"] = jwtErr.Detail
		}
	} else {
		// Extract detail from the error message for non-JWTError types
		errMsg := err.Error()

		// Handle standard error wrapping format
		if strings.Contains(errMsg, ": ") {
			parts := strings.SplitN(errMsg, ": ", 2)
			if len(parts) > 1 {
				result["message"] = parts[0]
				result["detail"] = parts[1]
			} else {
				result["message"] = errMsg
			}
		} else {
			result["message"] = errMsg
		}
	}

	return result
}

// ErrorHandler is a handler which is called when an error occurs in the
// JWTMiddleware. Among some general errors, this handler also determines the
// response of the JWTMiddleware when a token is not found or is invalid.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// DefaultErrorHandler is the default error handler implementation for the
// JWTMiddleware. If an error handler is not provided via the WithErrorHandler
// option this will be used.
func DefaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	var statusCode int
	var jwtErr *JWTError

	if errors.As(err, &jwtErr) {
		statusCode = jwtErr.StatusCode
	} else {
		// Determine status code based on error type
		switch {
		case errors.Is(err, ErrJWTMissing):
			statusCode = http.StatusBadRequest
		case errors.Is(err, ErrJWTInvalid):
			statusCode = http.StatusUnauthorized
		default:
			statusCode = http.StatusInternalServerError
		}
	}

	w.WriteHeader(statusCode)

	// Generate JSON response with consistent format
	result := ErrorToJSON(err)
	jsonStr := fmt.Sprintf(`{"message":"%s"`, result["message"])

	if detail, ok := result["detail"]; ok {
		jsonStr += fmt.Sprintf(`,"detail":"%s"`, detail)
	}

	jsonStr += "}"
	_, _ = w.Write([]byte(jsonStr))
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
