package jwtmiddleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

func TestDefaultErrorHandler(t *testing.T) {
	tests := []struct {
		name                 string
		err                  error
		wantStatus           int
		wantError            string
		wantErrorDescription string
		wantErrorCode        string
		wantWWWAuthenticate  string
	}{
		{
			name:       "ErrJWTMissing",
			err:        ErrJWTMissing,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_token",
			// Per RFC 6750 Section 3.1, when auth is missing, no error codes should be included
			wantErrorDescription: "",
			wantWWWAuthenticate:  `Bearer`,
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

			// Set context for backward compatibility - use DPoPDisabled mode for Bearer-only tests
			ctx := r.Context()
			ctx = core.SetDPoPMode(ctx, core.DPoPDisabled)
			ctx = core.SetAuthScheme(ctx, AuthSchemeBearer)
			r = r.WithContext(ctx)

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

func TestDefaultErrorHandler_DPoPErrors(t *testing.T) {
	tests := []struct {
		name                 string
		err                  error
		wantStatus           int
		wantError            string
		wantErrorDescription string
		wantErrorCode        string
		wantWWWAuthenticate  string
	}{
		{
			name:       "Missing token - DPoP Required mode only",
			err:        ErrJWTMissing,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_token",
			// Per RFC 6750 Section 3.1, when auth is missing, no error codes should be included
			// In DPoP Required mode, only DPoP challenge should be returned
			wantErrorDescription: "",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `"`,
		},
		{
			name:                 "DPoP proof missing",
			err:                  core.NewValidationError(core.ErrorCodeDPoPProofMissing, "DPoP proof is required", core.ErrInvalidDPoPProof),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_dpop_proof",
			wantErrorDescription: "DPoP proof is required",
			wantErrorCode:        "dpop_proof_missing",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="DPoP proof is required"`,
		},
		{
			name:                 "DPoP proof invalid",
			err:                  core.NewValidationError(core.ErrorCodeDPoPProofInvalid, "DPoP proof JWT validation failed", core.ErrInvalidDPoPProof),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_dpop_proof",
			wantErrorDescription: "DPoP proof JWT validation failed",
			wantErrorCode:        "dpop_proof_invalid",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="DPoP proof JWT validation failed"`,
		},
		{
			name:                 "DPoP HTM mismatch",
			err:                  core.NewValidationError(core.ErrorCodeDPoPHTMMismatch, "DPoP proof HTM does not match", core.ErrInvalidDPoPProof),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_dpop_proof",
			wantErrorDescription: "DPoP proof HTM does not match",
			wantErrorCode:        "dpop_htm_mismatch",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="DPoP proof HTM does not match"`,
		},
		{
			name:                 "DPoP HTU mismatch",
			err:                  core.NewValidationError(core.ErrorCodeDPoPHTUMismatch, "DPoP proof HTU does not match", core.ErrInvalidDPoPProof),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_dpop_proof",
			wantErrorDescription: "DPoP proof HTU does not match",
			wantErrorCode:        "dpop_htu_mismatch",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="DPoP proof HTU does not match"`,
		},
		{
			name:                 "DPoP proof expired",
			err:                  core.NewValidationError(core.ErrorCodeDPoPProofExpired, "DPoP proof is too old", core.ErrInvalidDPoPProof),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_dpop_proof",
			wantErrorDescription: "DPoP proof is too old",
			wantErrorCode:        "dpop_proof_expired",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="DPoP proof is too old"`,
		},
		{
			name:                 "DPoP proof too new",
			err:                  core.NewValidationError(core.ErrorCodeDPoPProofTooNew, "DPoP proof iat is in the future", core.ErrInvalidDPoPProof),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_dpop_proof",
			wantErrorDescription: "DPoP proof iat is in the future",
			wantErrorCode:        "dpop_proof_too_new",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="DPoP proof iat is in the future"`,
		},
		{
			name:                 "DPoP ATH mismatch",
			err:                  core.NewValidationError(core.ErrorCodeDPoPATHMismatch, "DPoP proof ath does not match access token hash", core.ErrInvalidDPoPProof),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_dpop_proof",
			wantErrorDescription: "DPoP proof ath does not match access token hash",
			wantErrorCode:        "dpop_ath_mismatch",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="DPoP proof ath does not match access token hash"`,
		},
		{
			name:                 "DPoP binding mismatch",
			err:                  core.NewValidationError(core.ErrorCodeDPoPBindingMismatch, "JKT does not match cnf claim", core.ErrDPoPBindingMismatch),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "JKT does not match cnf claim",
			wantErrorCode:        "dpop_binding_mismatch",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_token", error_description="JKT does not match cnf claim"`,
		},
		{
			name:                 "Bearer not allowed",
			err:                  core.NewValidationError(core.ErrorCodeBearerNotAllowed, "Bearer tokens are not allowed", core.ErrBearerNotAllowed),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_request",
			wantErrorDescription: "Bearer tokens are not allowed (DPoP required)",
			wantErrorCode:        "bearer_not_allowed",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_request", error_description="Bearer tokens are not allowed (DPoP required)"`,
		},
		{
			name:                 "DPoP not allowed",
			err:                  core.NewValidationError(core.ErrorCodeDPoPNotAllowed, "DPoP tokens are not allowed", core.ErrDPoPNotAllowed),
			wantStatus:           http.StatusBadRequest,
			wantError:            "invalid_request",
			wantErrorDescription: "DPoP tokens are not allowed (Bearer only)",
			wantErrorCode:        "dpop_not_allowed",
			wantWWWAuthenticate:  `Bearer error="invalid_request", error_description="DPoP tokens are not allowed (Bearer only)"`,
		},
		{
			name:                 "Config invalid",
			err:                  core.NewValidationError(core.ErrorCodeConfigInvalid, "Configuration is invalid", nil),
			wantStatus:           http.StatusUnauthorized,
			wantError:            "invalid_token",
			wantErrorDescription: "The access token is invalid",
			wantErrorCode:        "config_invalid",
			wantWWWAuthenticate:  `DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_token", error_description="The access token is invalid"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set context for DPoP required mode tests - use DPoPRequired to get DPoP-only challenges
			ctx := r.Context()
			ctx = core.SetDPoPMode(ctx, core.DPoPRequired)
			ctx = core.SetAuthScheme(ctx, AuthSchemeDPoP)
			r = r.WithContext(ctx)

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

func TestDefaultErrorHandler_DPoPAllowed_DualChallenges(t *testing.T) {
	// Tests for RFC 9449 Section 6.1: When DPoP is allowed (not required),
	// WWW-Authenticate should include BOTH Bearer and DPoP challenges.
	// This matches the CSV test cases for "dpop: {enabled: true, required: false}"
	tests := []struct {
		name                    string
		err                     error
		authScheme              AuthScheme
		wantStatus              int
		wantError               string
		wantErrorDescription    string
		wantErrorCode           string
		wantWWWAuthenticateAll  []string // All WWW-Authenticate headers (order matters)
		wantBearerChallenge     bool     // Should have Bearer challenge
		wantDPoPChallenge       bool     // Should have DPoP challenge
	}{
		{
			name:                   "Bearer scheme with DPoP proof - invalid_request",
			err:                    core.NewValidationError(core.ErrorCodeInvalidRequest, "Bearer scheme cannot be used when DPoP proof is present", nil),
			authScheme:             AuthSchemeBearer,
			wantStatus:             http.StatusBadRequest,
			wantError:              "invalid_request",
			wantErrorDescription:   "Bearer scheme cannot be used when DPoP proof is present",
			wantErrorCode:          "invalid_request",
			wantWWWAuthenticateAll: []string{
				`Bearer error="invalid_request", error_description="Bearer scheme cannot be used when DPoP proof is present"`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_request", error_description="Bearer scheme cannot be used when DPoP proof is present"`,
			},
			wantBearerChallenge: true,
			wantDPoPChallenge:   true,
		},
		{
			name:       "Missing token - both challenges",
			err:        ErrJWTMissing,
			authScheme: AuthSchemeUnknown,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_token",
			// Per RFC 6750 Section 3.1, when auth is missing, no error codes should be included
			wantErrorDescription: "",
			wantWWWAuthenticateAll: []string{
				`Bearer`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `"`,
			},
			wantBearerChallenge: true,
			wantDPoPChallenge:   true,
		},
		{
			name:                   "DPoP proof missing - Bearer + DPoP with error",
			err:                    core.NewValidationError(core.ErrorCodeDPoPProofMissing, "Operation indicated DPoP use but the request has no DPoP HTTP Header", core.ErrInvalidDPoPProof),
			authScheme:             AuthSchemeDPoP,
			wantStatus:             http.StatusBadRequest,
			wantError:              "invalid_dpop_proof",
			wantErrorDescription:   "Operation indicated DPoP use but the request has no DPoP HTTP Header",
			wantErrorCode:          "dpop_proof_missing",
			wantWWWAuthenticateAll: []string{
				`Bearer`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="Operation indicated DPoP use but the request has no DPoP HTTP Header"`,
			},
			wantBearerChallenge: true,
			wantDPoPChallenge:   true,
		},
		{
			name:                   "DPoP proof invalid - Bearer + DPoP with error",
			err:                    core.NewValidationError(core.ErrorCodeDPoPProofInvalid, "Failed to verify DPoP proof", core.ErrInvalidDPoPProof),
			authScheme:             AuthSchemeDPoP,
			wantStatus:             http.StatusBadRequest,
			wantError:              "invalid_dpop_proof",
			wantErrorDescription:   "Failed to verify DPoP proof",
			wantErrorCode:          "dpop_proof_invalid",
			wantWWWAuthenticateAll: []string{
				`Bearer`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="Failed to verify DPoP proof"`,
			},
			wantBearerChallenge: true,
			wantDPoPChallenge:   true,
		},
		{
			name:                   "DPoP HTM mismatch - Bearer + DPoP with error",
			err:                    core.NewValidationError(core.ErrorCodeDPoPHTMMismatch, "DPoP proof HTM claim does not match HTTP method", core.ErrInvalidDPoPProof),
			authScheme:             AuthSchemeDPoP,
			wantStatus:             http.StatusBadRequest,
			wantError:              "invalid_dpop_proof",
			wantErrorDescription:   "DPoP proof HTM claim does not match HTTP method",
			wantErrorCode:          "dpop_htm_mismatch",
			wantWWWAuthenticateAll: []string{
				`Bearer`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_dpop_proof", error_description="DPoP proof HTM claim does not match HTTP method"`,
			},
			wantBearerChallenge: true,
			wantDPoPChallenge:   true,
		},
		{
			name:                   "DPoP binding mismatch - Bearer + DPoP with error",
			err:                    core.NewValidationError(core.ErrorCodeDPoPBindingMismatch, "DPoP proof JKT does not match access token cnf claim", core.ErrDPoPBindingMismatch),
			authScheme:             AuthSchemeDPoP,
			wantStatus:             http.StatusUnauthorized,
			wantError:              "invalid_token",
			wantErrorDescription:   "DPoP proof JKT does not match access token cnf claim",
			wantErrorCode:          "dpop_binding_mismatch",
			wantWWWAuthenticateAll: []string{
				`Bearer`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_token", error_description="DPoP proof JKT does not match access token cnf claim"`,
			},
			wantBearerChallenge: true,
			wantDPoPChallenge:   true,
		},
		{
			name:                   "Bearer token with error - Bearer with error + DPoP",
			err:                    core.NewValidationError(core.ErrorCodeInvalidSignature, "signature verification failed", nil),
			authScheme:             AuthSchemeBearer,
			wantStatus:             http.StatusUnauthorized,
			wantError:              "invalid_token",
			wantErrorDescription:   "The access token signature is invalid",
			wantErrorCode:          "invalid_signature",
			wantWWWAuthenticateAll: []string{
				`Bearer error="invalid_token", error_description="The access token signature is invalid"`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `"`,
			},
			wantBearerChallenge: true,
			wantDPoPChallenge:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set context for DPoP ALLOWED mode (not required) - this should return BOTH challenges
			ctx := r.Context()
			ctx = core.SetDPoPMode(ctx, core.DPoPAllowed)
			ctx = core.SetAuthScheme(ctx, tt.authScheme)
			r = r.WithContext(ctx)

			DefaultErrorHandler(w, r, tt.err)

			// Check status code
			assert.Equal(t, tt.wantStatus, w.Code)

			// Check Content-Type
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			// Check WWW-Authenticate headers (multiple headers per RFC 9449 Section 6.1)
			authHeaders := w.Header().Values("WWW-Authenticate")
			assert.Len(t, authHeaders, len(tt.wantWWWAuthenticateAll), "Should have %d WWW-Authenticate headers", len(tt.wantWWWAuthenticateAll))

			// Verify both challenges are present
			if tt.wantBearerChallenge {
				foundBearer := false
				for _, h := range authHeaders {
					if len(h) >= 6 && h[:6] == "Bearer" {
						foundBearer = true
						break
					}
				}
				assert.True(t, foundBearer, "Should have Bearer challenge")
			}

			if tt.wantDPoPChallenge {
				foundDPoP := false
				for _, h := range authHeaders {
					if len(h) >= 4 && h[:4] == "DPoP" {
						foundDPoP = true
						break
					}
				}
				assert.True(t, foundDPoP, "Should have DPoP challenge")
			}

			// Check exact header values (order-dependent)
			for i, wantHeader := range tt.wantWWWAuthenticateAll {
				if i < len(authHeaders) {
					assert.Equal(t, wantHeader, authHeaders[i], "WWW-Authenticate header %d should match", i)
				}
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

func TestDefaultErrorHandler_EdgeCases(t *testing.T) {
	// Test edge cases and defensive branches for complete coverage
	tests := []struct {
		name                string
		err                 error
		dpopMode            core.DPoPMode
		authScheme          AuthScheme
		wantStatus          int
		wantError           string
		wantWWWAuthenticate []string
	}{
		{
			name:       "DPoP error when DPoP is disabled (defensive case)",
			err:        core.NewValidationError(core.ErrorCodeDPoPProofInvalid, "DPoP proof invalid", core.ErrInvalidDPoPProof),
			dpopMode:   core.DPoPDisabled,
			authScheme: AuthSchemeDPoP,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_dpop_proof",
			wantWWWAuthenticate: []string{
				`Bearer error="invalid_dpop_proof", error_description="DPoP proof invalid"`,
			},
		},
		{
			name:       "Invalid token error in DPoP allowed mode",
			err:        core.NewValidationError(core.ErrorCodeInvalidToken, "Token is invalid", nil),
			dpopMode:   core.DPoPAllowed,
			authScheme: AuthSchemeBearer,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_token",
			wantWWWAuthenticate: []string{
				`Bearer error="invalid_token", error_description="Token is invalid"`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `"`,
			},
		},
		{
			name:       "Custom claims validation error",
			err:        core.NewValidationError("custom_error", "Custom validation failed", nil),
			dpopMode:   core.DPoPAllowed,
			authScheme: AuthSchemeUnknown,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_token",
			wantWWWAuthenticate: []string{
				`Bearer error="invalid_token", error_description="The access token is invalid"`,
				`DPoP algs="` + validator.DPoPSupportedAlgorithms + `", error="invalid_token", error_description="The access token is invalid"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/test", nil)

			ctx := r.Context()
			ctx = core.SetDPoPMode(ctx, tt.dpopMode)
			ctx = core.SetAuthScheme(ctx, tt.authScheme)
			r = r.WithContext(ctx)

			DefaultErrorHandler(w, r, tt.err)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			authHeaders := w.Header().Values("WWW-Authenticate")
			assert.Len(t, authHeaders, len(tt.wantWWWAuthenticate))
			for i, wantHeader := range tt.wantWWWAuthenticate {
				if i < len(authHeaders) {
					assert.Equal(t, wantHeader, authHeaders[i])
				}
			}

			var resp ErrorResponse
			err := json.NewDecoder(w.Body).Decode(&resp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantError, resp.Error)
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
