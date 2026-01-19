package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// AuthScheme represents the authorization scheme used in the request.
// This is used to enforce RFC 9449 Section 6.1 which specifies that
// Bearer tokens without cnf claims should ignore DPoP headers.
type AuthScheme string

const (
	// AuthSchemeBearer represents Bearer token authorization.
	AuthSchemeBearer AuthScheme = "bearer"
	// AuthSchemeDPoP represents DPoP token authorization.
	AuthSchemeDPoP AuthScheme = "dpop"
	// AuthSchemeUnknown represents an unknown or missing authorization scheme.
	AuthSchemeUnknown AuthScheme = ""
)

// DPoPMode represents the operational mode for DPoP token validation.
type DPoPMode int

const (
	// DPoPAllowed accepts both Bearer and DPoP tokens (default, non-breaking).
	// This mode allows gradual migration from Bearer to DPoP tokens.
	DPoPAllowed DPoPMode = iota

	// DPoPRequired only accepts DPoP tokens and rejects Bearer tokens.
	// Use this mode when all clients have been upgraded to support DPoP.
	DPoPRequired

	// DPoPDisabled only accepts Bearer tokens and ignores DPoP headers.
	// Use this mode to explicitly opt-out of DPoP support.
	DPoPDisabled
)

// String returns a string representation of the DPoP mode.
func (m DPoPMode) String() string {
	switch m {
	case DPoPAllowed:
		return "DPoPAllowed"
	case DPoPRequired:
		return "DPoPRequired"
	case DPoPDisabled:
		return "DPoPDisabled"
	default:
		return fmt.Sprintf("DPoPMode(%d)", m)
	}
}

// DPoP-specific error codes
// Note: Error codes provide granular details for logging and debugging.
// The sentinel errors group these into two categories for error handling.
const (
	ErrorCodeDPoPProofMissing    = "dpop_proof_missing"
	ErrorCodeDPoPProofInvalid    = "dpop_proof_invalid"
	ErrorCodeDPoPBindingMismatch = "dpop_binding_mismatch"
	ErrorCodeDPoPHTMMismatch     = "dpop_htm_mismatch"
	ErrorCodeDPoPHTUMismatch     = "dpop_htu_mismatch"
	ErrorCodeDPoPATHMismatch     = "dpop_ath_mismatch"
	ErrorCodeDPoPProofExpired    = "dpop_proof_expired"
	ErrorCodeDPoPProofTooNew     = "dpop_proof_too_new"
	ErrorCodeBearerNotAllowed    = "bearer_not_allowed"
	ErrorCodeDPoPNotAllowed      = "dpop_not_allowed"
)

// DPoP-specific sentinel errors
// Per DPOP_ERRORS.md: All DPoP proof validation errors (except binding mismatch)
// are combined under ErrInvalidDPoPProof for simplified error handling.
var (
	// ErrInvalidDPoPProof is returned when DPoP proof validation fails.
	// This covers: missing proof, invalid JWT, HTM/HTU mismatch, expired/future iat.
	// The specific error code in ValidationError.Code provides granular details.
	ErrInvalidDPoPProof = errors.New("DPoP proof is invalid")

	// ErrDPoPBindingMismatch is returned when the JKT doesn't match the cnf claim.
	// This is kept separate as it indicates a token binding issue, not a proof validation issue.
	ErrDPoPBindingMismatch = errors.New("DPoP proof public key does not match token cnf claim")

	// ErrBearerNotAllowed is returned in DPoP required mode.
	ErrBearerNotAllowed = errors.New("bearer tokens are not allowed (DPoP required)")

	// ErrDPoPNotAllowed is returned in DPoP disabled mode.
	ErrDPoPNotAllowed = errors.New("DPoP tokens are not allowed (Bearer only)")
)

// DPoPProofClaims represents the essential claims extracted from a DPoP proof.
// This interface allows the core to work with different DPoP proof claim implementations.
type DPoPProofClaims interface {
	// GetJTI returns the unique identifier (jti) of the DPoP proof.
	GetJTI() string

	// GetHTM returns the HTTP method (htm) from the DPoP proof.
	GetHTM() string

	// GetHTU returns the HTTP URI (htu) from the DPoP proof.
	GetHTU() string

	// GetIAT returns the issued-at timestamp (iat) from the DPoP proof.
	GetIAT() int64

	// GetATH returns the access token hash (ath) from the DPoP proof, if present.
	// Returns empty string if the ath claim is not included in the proof.
	GetATH() string

	// GetPublicKeyThumbprint returns the calculated JKT from the DPoP proof's JWK.
	GetPublicKeyThumbprint() string

	// GetPublicKey returns the public key from the DPoP proof's JWK.
	GetPublicKey() any
}

// TokenClaims represents the essential claims from an access token.
// This interface allows the core to work with different token claim implementations.
type TokenClaims interface {
	// GetConfirmationJKT returns the jkt from the cnf claim, or empty string if not present.
	GetConfirmationJKT() string

	// HasConfirmation returns true if the token has a cnf claim.
	HasConfirmation() bool
}

// DPoPContext contains validated DPoP information for the application.
// This is created by Core after successful DPoP validation and can be stored
// in the request context alongside the validated claims.
type DPoPContext struct {
	// PublicKeyThumbprint (jkt) from the validated DPoP proof.
	// Can be used for session binding, audit logging, rate limiting, etc.
	PublicKeyThumbprint string

	// IssuedAt timestamp from the DPoP proof.
	// Useful for audit trails and debugging.
	IssuedAt time.Time

	// TokenType is always "DPoP" when this context exists.
	// Helps distinguish DPoP tokens from Bearer tokens.
	TokenType string

	// PublicKey is the validated public key from the DPoP proof JWK.
	// Can be used for additional cryptographic operations if needed.
	PublicKey any

	// DPoPProof is the raw DPoP proof JWT string.
	// Useful for logging and audit purposes.
	DPoPProof string
}

// CheckTokenWithDPoP validates an access token with optional DPoP proof.
// This is the primary validation method that handles both Bearer and DPoP tokens.
//
// Parameters:
//   - ctx: Request context
//   - accessToken: JWT access token string
//   - authScheme: The authorization scheme from the request (Bearer, DPoP, or Unknown)
//   - dpopProof: DPoP proof JWT string (empty for Bearer tokens)
//   - httpMethod: HTTP method for HTM validation (empty for Bearer tokens)
//   - requestURL: Full request URL for HTU validation (empty for Bearer tokens)
//
// Returns:
//   - claims: Validated token claims (TokenClaims interface)
//   - dpopCtx: DPoP context (nil for Bearer tokens)
//   - error: Validation error or nil
//
// The authScheme parameter is used to enforce RFC 9449 Section 6.1 which specifies
// that Bearer tokens without cnf claims should ignore DPoP headers.
//
// When dpopProof is empty, this method behaves identically to CheckToken for Bearer tokens.
func (c *Core) CheckTokenWithDPoP(
	ctx context.Context,
	accessToken string,
	authScheme AuthScheme,
	dpopProof string,
	httpMethod string,
	requestURL string,
) (claims any, dpopCtx *DPoPContext, err error) {
	// Step 1: Handle empty token case
	if accessToken == "" {
		if c.credentialsOptional {
			c.logDebug("No token provided, but credentials are optional")
			return nil, nil, nil
		}

		c.logWarn("No token provided and credentials are required")

		// If DPoP proof is present but Authorization header is missing, it's a malformed request (400)
		// Per RFC 6750 Section 3.1: Malformed requests should return bare WWW-Authenticate challenge
		if dpopProof != "" {
			return nil, nil, NewValidationError(
				ErrorCodeInvalidRequest,
				"", // Empty per RFC 6750 Section 3.1 for malformed requests
				ErrInvalidRequest,
			)
		}

		// In Required mode, missing auth should return invalid_request (400)
		if c.dpopMode == DPoPRequired {
			return nil, nil, NewValidationError(
				ErrorCodeInvalidRequest,
				"Authorization header is required",
				ErrJWTMissing,
			)
		}
		return nil, nil, ErrJWTMissing
	}

	// Step 1.5: Early scheme validation (check scheme BEFORE token validation)
	// This prevents revealing token validity information when the scheme is not allowed.
	//
	// DPoP Required mode: Only DPoP scheme is allowed
	// Per RFC 6750 Section 3.1: unsupported authentication methods should return
	// invalid_request with NO error_description (bare WWW-Authenticate challenge)
	if c.dpopMode == DPoPRequired && authScheme == AuthSchemeBearer {
		c.logError("Bearer authorization scheme used but DPoP Required mode only accepts DPoP scheme")
		// Per RFC 6750 Section 3.1: unsupported authentication methods should return
		// invalid_request with NO error_description (bare WWW-Authenticate challenge)
		return nil, nil, NewValidationError(
			ErrorCodeInvalidRequest,
			"", // Empty per RFC 6750 Section 3.1 for unsupported authentication methods
			ErrInvalidRequest,
		)
	}

	// DPoP Disabled mode: Only Bearer scheme is allowed
	// Per RFC 6750 Section 3.1: unsupported authentication methods should return
	// invalid_request with NO error_description (bare WWW-Authenticate challenge)
	if c.dpopMode == DPoPDisabled && authScheme == AuthSchemeDPoP {
		c.logError("DPoP authorization scheme used but DPoP is disabled")
		// Per RFC 6750 Section 3.1: unsupported authentication methods should return
		// invalid_request with NO error_description (bare WWW-Authenticate challenge)
		return nil, nil, NewValidationError(
			ErrorCodeDPoPNotAllowed,
			"", // Empty per RFC 6750 Section 3.1 for unsupported authentication methods
			ErrDPoPNotAllowed,
		)
	}

	// Step 2: Validate the access token (always required)
	start := time.Now()
	validatedClaims, err := c.validator.ValidateToken(ctx, accessToken)
	duration := time.Since(start)

	if err != nil {
		c.logError("Access token validation failed", "error", err, "duration", duration)
		return nil, nil, err
	}

	c.logDebug("Access token validated successfully", "duration", duration)

	// Step 3: Determine token type based on scheme and proof presence
	hasDPoPProof := dpopProof != ""

	// Try to cast to TokenClaims to check for cnf claim
	tokenClaims, supportsConfirmation := validatedClaims.(TokenClaims)
	hasConfirmationClaim := supportsConfirmation && tokenClaims.HasConfirmation()

	// Step 4: Handle DPoP Disabled mode
	// When DPoP is disabled, the server behaves as if it's unaware of DPoP.
	// Per RFC 9449 Section 7.2, servers unaware of DPoP accept DPoP-bound tokens as bearer tokens.
	// Note: DPoP scheme was already rejected at Step 1.5
	if c.dpopMode == DPoPDisabled {
		// Ignore DPoP header in disabled mode - treat as Bearer-only mode
		if hasDPoPProof {
			c.logDebug("DPoP header ignored (DPoP disabled, treating as Bearer-only)")
		}
		return c.handleBearerToken(validatedClaims, hasConfirmationClaim, authScheme)
	}

	// Step 5: Check if DPoP scheme is used with non-TokenClaims type
	// If the claims type doesn't implement TokenClaims, it cannot support DPoP confirmation
	if authScheme == AuthSchemeDPoP && !supportsConfirmation {
		c.logError("DPoP scheme used but token claims do not implement TokenClaims interface")
		return nil, nil, NewValidationError(
			ErrorCodeConfigInvalid,
			"Token claims do not support DPoP confirmation (must implement TokenClaims interface)",
			errors.New("token claims must implement TokenClaims interface for DPoP validation"),
		)
	}

	// Step 6: RFC 9449 Section 7.2 - Bearer scheme with DPoP proof handling
	// "When a resource server receives a request with both a DPoP proof and an access token
	// in the Authorization header using the Bearer scheme, the resource server MUST reject the request."
	//
	// However, we must distinguish between two cases:
	// 1. DPoP-bound token (has cnf) + Bearer scheme → 401 invalid_token (wrong scheme for bound token)
	// 2. Regular token (no cnf) + Bearer scheme + DPoP proof → 400 invalid_request (RFC 9449 Section 7.2)
	//
	// The first case is a token validation error (the token requires DPoP scheme).
	// The second case is a request format error (client sent conflicting auth mechanisms).
	if authScheme == AuthSchemeBearer && hasDPoPProof {
		if hasConfirmationClaim {
			// DPoP-bound token used with wrong scheme
			c.logError("DPoP-bound token (with cnf claim) used with Bearer scheme instead of DPoP scheme")
			return nil, nil, NewValidationError(
				ErrorCodeInvalidToken,
				"DPoP-bound token requires the DPoP authentication scheme, not Bearer",
				ErrJWTInvalid,
			)
		}
		// Regular token with both Bearer and DPoP mechanisms
		c.logError("Bearer authorization scheme used with DPoP proof header (RFC 9449 Section 7.2 violation)")
		return nil, nil, NewValidationError(
			ErrorCodeInvalidRequest,
			"Bearer scheme cannot be used when DPoP proof is present (use DPoP scheme instead)",
			ErrInvalidRequest,
		)
	}

	// Step 7: RFC 9449 Section 7.1 - DPoP scheme requires DPoP-bound token
	// If Authorization scheme is DPoP but token has no cnf claim, reject the request.
	// DPoP scheme MUST only be used with DPoP-bound tokens (containing cnf claim).
	if authScheme == AuthSchemeDPoP && !hasConfirmationClaim {
		c.logError("DPoP authorization scheme used with non-DPoP-bound token (missing cnf claim)")
		return nil, nil, NewValidationError(
			ErrorCodeInvalidToken,
			"DPoP scheme requires a DPoP-bound access token (token must contain cnf claim)",
			ErrInvalidToken,
		)
	}

	// Step 8: Handle Bearer token flow (no DPoP proof)
	if !hasDPoPProof {
		return c.handleBearerToken(validatedClaims, hasConfirmationClaim, authScheme)
	}

	// Step 9: Validate DPoP proof
	// At this point: DPoP is enabled (Allowed or Required), and we have a DPoP proof to validate
	return c.validateDPoPToken(ctx, validatedClaims, tokenClaims, supportsConfirmation,
		hasConfirmationClaim, accessToken, dpopProof, httpMethod, requestURL)
}

// handleBearerToken processes Bearer token validation logic.
// The authScheme parameter is used for logging purposes to distinguish
// between true Bearer tokens and Bearer tokens with ignored DPoP headers.
// Note: Scheme validation (Required/Disabled modes) happens at Step 1.5 before this function.
func (c *Core) handleBearerToken(claims any, hasConfirmationClaim bool, authScheme AuthScheme) (any, *DPoPContext, error) {
	// When DPoP is enabled (Allowed or Required), check if token has cnf claim but no DPoP proof
	// RFC 9449 Section 6.1: DPoP-bound tokens (with cnf) require DPoP proof when DPoP is enabled
	// Note: When DPoP is disabled, we don't enforce this check (server is "unaware" of DPoP)
	if c.dpopMode != DPoPDisabled && hasConfirmationClaim {
		// DPoP-bound token used with Bearer scheme (no proof)
		// This is a token validation error (401) - the token type is wrong for Bearer scheme
		if authScheme == AuthSchemeBearer {
			c.logError("DPoP-bound token requires the DPoP authentication scheme, not Bearer",
				"authScheme", string(authScheme))
			return nil, nil, NewValidationError(
				ErrorCodeInvalidToken,
				"DPoP-bound token requires the DPoP authentication scheme, not Bearer",
				ErrJWTInvalid,
			)
		}
		// DPoP scheme but proof is missing - this is a DPoP proof error (400)
		c.logError("Token has cnf claim but no DPoP proof provided",
			"authScheme", string(authScheme))
		return nil, nil, NewValidationError(
			ErrorCodeDPoPProofMissing,
			"DPoP proof is required for DPoP-bound tokens",
			ErrInvalidDPoPProof,
		)
	}

	c.logDebug("Bearer token accepted",
		"authScheme", string(authScheme),
		"dpopMode", c.dpopMode.String())

	return claims, nil, nil
}

// validateDPoPToken validates a DPoP token with proof.
func (c *Core) validateDPoPToken(
	ctx context.Context,
	claims any,
	tokenClaims TokenClaims,
	supportsConfirmation bool,
	hasConfirmationClaim bool,
	accessToken string,
	dpopProof string,
	httpMethod string,
	requestURL string,
) (any, *DPoPContext, error) {
	// Step 1: Check if claims type implements TokenClaims interface
	if !supportsConfirmation {
		c.logError("Token claims do not implement TokenClaims interface")
		return nil, nil, NewValidationError(
			ErrorCodeConfigInvalid,
			"Token claims do not support DPoP confirmation",
			errors.New("token claims must implement TokenClaims interface for DPoP validation"),
		)
	}

	// Step 2: Check if token has cnf claim
	if !hasConfirmationClaim {
		c.logError("DPoP proof provided but token has no cnf claim")
		return nil, nil, NewValidationError(
			ErrorCodeDPoPBindingMismatch,
			"Token must have cnf claim for DPoP binding",
			ErrDPoPBindingMismatch,
		)
	}

	// Step 3: Validate DPoP proof JWT
	proofClaims, err := c.validateDPoPProofJWT(ctx, dpopProof)
	if err != nil {
		return nil, nil, err
	}

	// Step 4: Verify JKT binding
	expectedJKT := tokenClaims.GetConfirmationJKT()
	actualJKT := proofClaims.GetPublicKeyThumbprint()
	if err := c.validateJKTBinding(expectedJKT, actualJKT); err != nil {
		return nil, nil, err
	}

	// Step 5: Validate ATH (Access Token Hash) if present per RFC 9449 Section 4.2
	if err := c.validateATH(proofClaims.GetATH(), accessToken); err != nil {
		return nil, nil, err
	}

	// Step 6: Validate HTM and HTU
	if err := c.validateHTMAndHTU(proofClaims, httpMethod, requestURL); err != nil {
		return nil, nil, err
	}

	// Step 7: Validate IAT freshness
	proofIAT := proofClaims.GetIAT()
	if err := c.validateIATFreshness(proofIAT); err != nil {
		return nil, nil, err
	}

	// Step 8: Create DPoP context
	dpopCtx := &DPoPContext{
		PublicKeyThumbprint: actualJKT,
		IssuedAt:            time.Unix(proofIAT, 0),
		TokenType:           "DPoP",
		PublicKey:           proofClaims.GetPublicKey(),
		DPoPProof:           dpopProof,
	}

	c.logInfo("DPoP token validated successfully", "jkt", actualJKT)
	return claims, dpopCtx, nil
}

// validateDPoPProofJWT validates the DPoP proof JWT and returns the claims.
func (c *Core) validateDPoPProofJWT(ctx context.Context, dpopProof string) (DPoPProofClaims, error) {
	dpopStart := time.Now()
	proofClaims, err := c.validator.ValidateDPoPProof(ctx, dpopProof)
	dpopDuration := time.Since(dpopStart)

	if err != nil {
		c.logError("DPoP proof validation failed", "error", err, "duration", dpopDuration)
		return nil, NewValidationError(
			ErrorCodeDPoPProofInvalid,
			"DPoP proof JWT validation failed",
			ErrInvalidDPoPProof,
		)
	}

	c.logDebug("DPoP proof validated successfully", "duration", dpopDuration)
	return proofClaims, nil
}

// validateJKTBinding verifies that the DPoP proof JKT matches the token's cnf.jkt claim.
func (c *Core) validateJKTBinding(expectedJKT, actualJKT string) error {
	if expectedJKT != actualJKT {
		c.logError("DPoP JKT mismatch", "expected", expectedJKT, "actual", actualJKT)
		return NewValidationError(
			ErrorCodeDPoPBindingMismatch,
			fmt.Sprintf("DPoP proof JKT %q does not match token cnf.jkt %q", actualJKT, expectedJKT),
			ErrDPoPBindingMismatch,
		)
	}
	return nil
}

// validateATH validates the ATH (Access Token Hash) claim.
// Per RFC 9449 Section 4.2, the ath claim is REQUIRED for sender-constraining security.
// Without ath validation, a stolen access token could be used with a new DPoP proof.
func (c *Core) validateATH(proofATH, accessToken string) error {
	if proofATH == "" {
		c.logError("DPoP proof missing required ath claim")
		return NewValidationError(
			ErrorCodeDPoPATHMismatch,
			"DPoP proof must include ath (access token hash) claim",
			ErrInvalidDPoPProof,
		)
	}

	expectedATH := computeAccessTokenHash(accessToken)
	if proofATH != expectedATH {
		c.logError("DPoP ATH mismatch", "expected", expectedATH, "actual", proofATH)
		return NewValidationError(
			ErrorCodeDPoPATHMismatch,
			fmt.Sprintf("DPoP proof ath %q does not match access token hash %q", proofATH, expectedATH),
			ErrInvalidDPoPProof,
		)
	}

	c.logDebug("DPoP ATH validated successfully")
	return nil
}

// validateHTMAndHTU validates the HTM (HTTP method) and HTU (HTTP URI) claims.
func (c *Core) validateHTMAndHTU(proofClaims DPoPProofClaims, httpMethod, requestURL string) error {
	if proofClaims.GetHTM() != httpMethod {
		c.logError("DPoP HTM mismatch", "expected", httpMethod, "actual", proofClaims.GetHTM())
		return NewValidationError(
			ErrorCodeDPoPHTMMismatch,
			fmt.Sprintf("DPoP proof HTM %q does not match request method %q", proofClaims.GetHTM(), httpMethod),
			ErrInvalidDPoPProof,
		)
	}

	if proofClaims.GetHTU() != requestURL {
		c.logError("DPoP HTU mismatch", "expected", requestURL, "actual", proofClaims.GetHTU())
		return NewValidationError(
			ErrorCodeDPoPHTUMismatch,
			fmt.Sprintf("DPoP proof HTU %q does not match request URL %q", proofClaims.GetHTU(), requestURL),
			ErrInvalidDPoPProof,
		)
	}

	return nil
}

// validateIATFreshness validates that the DPoP proof IAT is within acceptable bounds.
func (c *Core) validateIATFreshness(proofIAT int64) error {
	now := time.Now().Unix()

	// Check if proof is too far in the future (beyond clock skew leeway)
	if proofIAT > (now + int64(c.dpopIATLeeway.Seconds())) {
		c.logError("DPoP proof iat is too far in the future",
			"iat", proofIAT, "now", now, "leeway", c.dpopIATLeeway.Seconds())
		return NewValidationError(
			ErrorCodeDPoPProofTooNew,
			fmt.Sprintf("DPoP proof iat %d is too far in the future", proofIAT),
			ErrInvalidDPoPProof,
		)
	}

	// Check if proof is too old (expired)
	if proofIAT < (now - int64(c.dpopProofOffset.Seconds())) {
		c.logError("DPoP proof is expired",
			"iat", proofIAT, "now", now, "offset", c.dpopProofOffset.Seconds())
		return NewValidationError(
			ErrorCodeDPoPProofExpired,
			fmt.Sprintf("DPoP proof is too old (iat: %d)", proofIAT),
			ErrInvalidDPoPProof,
		)
	}

	return nil
}

// logError logs an error message if the logger is configured.
func (c *Core) logError(msg string, args ...any) {
	if c.logger != nil {
		c.logger.Error(msg, args...)
	}
}

// logWarn logs a warning message if the logger is configured.
func (c *Core) logWarn(msg string, args ...any) {
	if c.logger != nil {
		c.logger.Warn(msg, args...)
	}
}

// logDebug logs a debug message if the logger is configured.
func (c *Core) logDebug(msg string, args ...any) {
	if c.logger != nil {
		c.logger.Debug(msg, args...)
	}
}

// logInfo logs an info message if the logger is configured.
func (c *Core) logInfo(msg string, args ...any) {
	if c.logger != nil {
		c.logger.Info(msg, args...)
	}
}

// computeAccessTokenHash computes the SHA-256 hash of the access token
// and returns it as a base64url-encoded string (without padding) per RFC 9449.
// This is used for validating the ath claim in DPoP proofs.
func computeAccessTokenHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
