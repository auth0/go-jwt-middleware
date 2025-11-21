package jwtmiddleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v3/core"
)

func TestDefaultErrorHandler(t *testing.T) {
	tests := []struct {
		name                   string
		err                    error
		wantStatus             int
		wantError              string
		wantErrorDescription   string
		wantErrorCode          string
		wantWWWAuthenticate    string
	}{
		{
			name:                 "ErrJWTMissing",
			err:                  ErrJWTMissing,
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "JWT is missing",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="JWT is missing"`,
		},
		{
			name:                 "ErrJWTInvalid",
			err:                  ErrJWTInvalid,
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "JWT is invalid",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="JWT is invalid"`,
		},
		{
			name:                 "token expired",
			err:                  core.NewValidationError(core.ErrorCodeTokenExpired, "token expired", nil),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "The access token expired",
			wantErrorCode:        "token_expired",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="The access token expired"`,
		},
		{
			name:                 "token not yet valid",
			err:                  core.NewValidationError(core.ErrorCodeTokenNotYetValid, "token not yet valid", nil),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "The access token is not yet valid",
			wantErrorCode:        "token_not_yet_valid",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="The access token is not yet valid"`,
		},
		{
			name:                 "invalid signature",
			err:                  core.NewValidationError(core.ErrorCodeInvalidSignature, "invalid signature", nil),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "The access token signature is invalid",
			wantErrorCode:        "invalid_signature",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="The access token signature is invalid"`,
		},
		{
			name:                 "token malformed",
			err:                  core.NewValidationError(core.ErrorCodeTokenMalformed, "malformed token", nil),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_request",
			wantErrorDescription: "The access token is malformed",
			wantErrorCode:        "token_malformed",
			wantWWWAuthenticate:  `Bearer error="invalid_request", error_description="The access token is malformed"`,
		},
		{
			name:                 "invalid issuer",
			err:                  core.NewValidationError(core.ErrorCodeInvalidIssuer, "invalid issuer", nil),
			wantStatus:           http.StatusForbidden,
			wantError:            "insufficient_scope",
			wantErrorDescription: "The access token was issued by an untrusted issuer",
			wantErrorCode:        "invalid_issuer",
			wantWWWAuthenticate:  `Bearer error="insufficient_scope", error_description="The access token was issued by an untrusted issuer"`,
		},
		{
			name:                 "invalid audience",
			err:                  core.NewValidationError(core.ErrorCodeInvalidAudience, "invalid audience", nil),
			wantStatus:           http.StatusForbidden,
			wantError:            "insufficient_scope",
			wantErrorDescription: "The access token audience does not match",
			wantErrorCode:        "invalid_audience",
			wantWWWAuthenticate:  `Bearer error="insufficient_scope", error_description="The access token audience does not match"`,
		},
		{
			name:                 "invalid algorithm",
			err:                  core.NewValidationError(core.ErrorCodeInvalidAlgorithm, "invalid algorithm", nil),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "The access token uses an unsupported algorithm",
			wantErrorCode:        "invalid_algorithm",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="The access token uses an unsupported algorithm"`,
		},
		{
			name:                 "JWKS fetch failed",
			err:                  core.NewValidationError(core.ErrorCodeJWKSFetchFailed, "jwks fetch failed", nil),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "Unable to verify the access token",
			wantErrorCode:        "jwks_fetch_failed",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="Unable to verify the access token"`,
		},
		{
			name:                 "JWKS key not found",
			err:                  core.NewValidationError(core.ErrorCodeJWKSKeyNotFound, "key not found", nil),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "Unable to verify the access token",
			wantErrorCode:        "jwks_key_not_found",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="Unable to verify the access token"`,
		},
		{
			name:                 "unknown validation error",
			err:                  core.NewValidationError("unknown_code", "unknown error", nil),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "The access token is invalid",
			wantErrorCode:        "unknown_code",
			wantWWWAuthenticate:  `Bearer error="invalid_token", error_description="The access token is invalid"`,
		},
		{
			name:                 "generic error",
			err:                  assert.AnError,
			wantStatus:           http.StatusInternalServerError,
			wantError:            "server_error",
			wantErrorDescription: "An internal error occurred while processing the request",
			wantWWWAuthenticate:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/test", nil)

			DefaultErrorHandler(w, r, tt.err)

			// Check status code
			assert.Equal(t, tt.wantStatus, w.Code)

			// Check Content-Type
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			// Check WWW-Authenticate header
			if tt.wantWWWAuthenticate != "" {
				assert.Equal(t, tt.wantWWWAuthenticate, w.Header().Get("WWW-Authenticate"))
			} else {
				assert.Empty(t, w.Header().Get("WWW-Authenticate"))
			}

			// Check response body
			var resp ErrorResponse
			err := json.NewDecoder(w.Body).Decode(&resp)
			require.NoError(t, err)

			assert.Equal(t, tt.wantError, resp.Error)
			assert.Equal(t, tt.wantErrorDescription, resp.ErrorDescription)
			if tt.wantErrorCode != "" {
				assert.Equal(t, tt.wantErrorCode, resp.ErrorCode)
			}
		})
	}
}

func TestErrorResponse_JSON(t *testing.T) {
	tests := []struct {
		name     string
		response ErrorResponse
		wantJSON string
	}{
		{
			name: "all fields",
			response: ErrorResponse{
				Error:            "invalid_token",
				ErrorDescription: "The token expired",
				ErrorCode:        "token_expired",
			},
			wantJSON: `{"error":"invalid_token","error_description":"The token expired","error_code":"token_expired"}`,
		},
		{
			name: "without error code",
			response: ErrorResponse{
				Error:            "invalid_token",
				ErrorDescription: "JWT is invalid",
			},
			wantJSON: `{"error":"invalid_token","error_description":"JWT is invalid"}`,
		},
		{
			name: "without description",
			response: ErrorResponse{
				Error: "server_error",
			},
			wantJSON: `{"error":"server_error"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.response)
			require.NoError(t, err)
			assert.JSONEq(t, tt.wantJSON, string(data))
		})
	}
}
