package core

import (
	"context"
	"errors"
	"fmt"
	"time"
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
//   - dpopProof: DPoP proof JWT string (empty for Bearer tokens)
//   - httpMethod: HTTP method for HTM validation (empty for Bearer tokens)
//   - requestURL: Full request URL for HTU validation (empty for Bearer tokens)
//
// Returns:
//   - claims: Validated token claims (TokenClaims interface)
//   - dpopCtx: DPoP context (nil for Bearer tokens)
//   - error: Validation error or nil
//
// When dpopProof is empty, this method behaves identically to CheckToken for Bearer tokens.
func (c *Core) CheckTokenWithDPoP(
	ctx context.Context,
	accessToken string,
	dpopProof string,
	httpMethod string,
	requestURL string,
) (claims any, dpopCtx *DPoPContext, err error) {
	// Step 1: Handle empty token case
	if accessToken == "" {
		if c.credentialsOptional {
			if c.logger != nil {
				c.logger.Debug("No token provided, but credentials are optional")
			}
			return nil, nil, nil
		}

		if c.logger != nil {
			c.logger.Warn("No token provided and credentials are required")
		}

		return nil, nil, ErrJWTMissing
	}

	// Step 2: Validate the access token (always required)
	start := time.Now()
	validatedClaims, err := c.validator.ValidateToken(ctx, accessToken)
	duration := time.Since(start)

	if err != nil {
		if c.logger != nil {
			c.logger.Error("Access token validation failed", "error", err, "duration", duration)
		}
		return nil, nil, err
	}

	if c.logger != nil {
		c.logger.Debug("Access token validated successfully", "duration", duration)
	}

	// Step 3: Determine if this is a Bearer or DPoP token
	isDPoPToken := dpopProof != ""

	// Try to cast to TokenClaims to check for cnf claim
	tokenClaims, supportsConfirmation := validatedClaims.(TokenClaims)
	hasConfirmationClaim := supportsConfirmation && tokenClaims.HasConfirmation()

	// Step 4: Handle Bearer token flow
	if !isDPoPToken {
		return c.handleBearerToken(validatedClaims, hasConfirmationClaim)
	}

	// Step 5: Handle DPoP token flow
	if c.dpopMode == DPoPDisabled {
		if c.logger != nil {
			c.logger.Warn("DPoP header present but DPoP is disabled, treating as Bearer token")
		}
		return c.handleBearerToken(validatedClaims, hasConfirmationClaim)
	}

	// Step 6: Validate DPoP proof
	return c.validateDPoPToken(ctx, validatedClaims, tokenClaims, supportsConfirmation,
		hasConfirmationClaim, dpopProof, httpMethod, requestURL)
}

// handleBearerToken processes Bearer token validation logic.
func (c *Core) handleBearerToken(claims any, hasConfirmationClaim bool) (any, *DPoPContext, error) {
	// Check if token has cnf claim but no DPoP proof (orphaned DPoP token)
	if hasConfirmationClaim {
		if c.logger != nil {
			c.logger.Error("Token has cnf claim but no DPoP proof provided")
		}
		return nil, nil, NewValidationError(
			ErrorCodeDPoPProofMissing,
			"DPoP proof is required for DPoP-bound tokens",
			ErrInvalidDPoPProof,
		)
	}

	// Check if Bearer tokens are allowed
	if c.dpopMode == DPoPRequired {
		if c.logger != nil {
			c.logger.Error("Bearer token provided but DPoP is required")
		}
		return nil, nil, NewValidationError(
			ErrorCodeBearerNotAllowed,
			"Bearer tokens are not allowed (DPoP required)",
			ErrBearerNotAllowed,
		)
	}

	if c.logger != nil {
		c.logger.Debug("Bearer token accepted")
	}

	return claims, nil, nil
}

// validateDPoPToken validates a DPoP token with proof.
func (c *Core) validateDPoPToken(
	ctx context.Context,
	claims any,
	tokenClaims TokenClaims,
	supportsConfirmation bool,
	hasConfirmationClaim bool,
	dpopProof string,
	httpMethod string,
	requestURL string,
) (any, *DPoPContext, error) {
	// Step 1: Check if claims type implements TokenClaims interface
	if !supportsConfirmation {
		// Claims type doesn't implement TokenClaims interface
		if c.logger != nil {
			c.logger.Error("Token claims do not implement TokenClaims interface")
		}
		return nil, nil, NewValidationError(
			ErrorCodeConfigInvalid,
			"Token claims do not support DPoP confirmation",
			errors.New("token claims must implement TokenClaims interface for DPoP validation"),
		)
	}

	// Step 2: Check if token has cnf claim
	if !hasConfirmationClaim {
		if c.logger != nil {
			c.logger.Error("DPoP proof provided but token has no cnf claim")
		}
		return nil, nil, NewValidationError(
			ErrorCodeDPoPBindingMismatch,
			"Token must have cnf claim for DPoP binding",
			ErrDPoPBindingMismatch,
		)
	}

	// Step 2: Validate DPoP proof JWT
	dpopStart := time.Now()
	proofClaims, err := c.validator.ValidateDPoPProof(ctx, dpopProof)
	dpopDuration := time.Since(dpopStart)

	if err != nil {
		if c.logger != nil {
			c.logger.Error("DPoP proof validation failed", "error", err, "duration", dpopDuration)
		}
		return nil, nil, NewValidationError(
			ErrorCodeDPoPProofInvalid,
			"DPoP proof JWT validation failed",
			ErrInvalidDPoPProof,
		)
	}

	if c.logger != nil {
		c.logger.Debug("DPoP proof validated successfully", "duration", dpopDuration)
	}

	// Step 3: Verify JKT binding
	expectedJKT := tokenClaims.GetConfirmationJKT()
	actualJKT := proofClaims.GetPublicKeyThumbprint()

	if expectedJKT != actualJKT {
		if c.logger != nil {
			c.logger.Error("DPoP JKT mismatch", "expected", expectedJKT, "actual", actualJKT)
		}
		return nil, nil, NewValidationError(
			ErrorCodeDPoPBindingMismatch,
			fmt.Sprintf("DPoP proof JKT %q does not match token cnf.jkt %q", actualJKT, expectedJKT),
			ErrDPoPBindingMismatch,
		)
	}

	// Step 4: Validate HTM (HTTP method)
	if proofClaims.GetHTM() != httpMethod {
		if c.logger != nil {
			c.logger.Error("DPoP HTM mismatch", "expected", httpMethod, "actual", proofClaims.GetHTM())
		}
		return nil, nil, NewValidationError(
			ErrorCodeDPoPHTMMismatch,
			fmt.Sprintf("DPoP proof HTM %q does not match request method %q", proofClaims.GetHTM(), httpMethod),
			ErrInvalidDPoPProof,
		)
	}

	// Step 5: Validate HTU (HTTP URI)
	if proofClaims.GetHTU() != requestURL {
		if c.logger != nil {
			c.logger.Error("DPoP HTU mismatch", "expected", requestURL, "actual", proofClaims.GetHTU())
		}
		return nil, nil, NewValidationError(
			ErrorCodeDPoPHTUMismatch,
			fmt.Sprintf("DPoP proof HTU %q does not match request URL %q", proofClaims.GetHTU(), requestURL),
			ErrInvalidDPoPProof,
		)
	}

	// Step 6: Validate IAT freshness
	now := time.Now().Unix()
	proofIAT := proofClaims.GetIAT()

	// Check if proof is too far in the future (beyond clock skew leeway)
	if proofIAT > (now + int64(c.dpopIATLeeway.Seconds())) {
		if c.logger != nil {
			c.logger.Error("DPoP proof iat is too far in the future",
				"iat", proofIAT, "now", now, "leeway", c.dpopIATLeeway.Seconds())
		}
		return nil, nil, NewValidationError(
			ErrorCodeDPoPProofTooNew,
			fmt.Sprintf("DPoP proof iat %d is too far in the future", proofIAT),
			ErrInvalidDPoPProof,
		)
	}

	// Check if proof is too old (expired)
	if proofIAT < (now - int64(c.dpopProofOffset.Seconds())) {
		if c.logger != nil {
			c.logger.Error("DPoP proof is expired",
				"iat", proofIAT, "now", now, "offset", c.dpopProofOffset.Seconds())
		}
		return nil, nil, NewValidationError(
			ErrorCodeDPoPProofExpired,
			fmt.Sprintf("DPoP proof is too old (iat: %d)", proofIAT),
			ErrInvalidDPoPProof,
		)
	}

	// Step 7: Create DPoP context
	dpopCtx := &DPoPContext{
		PublicKeyThumbprint: actualJKT,
		IssuedAt:            time.Unix(proofIAT, 0),
		TokenType:           "DPoP",
		PublicKey:           proofClaims.GetPublicKey(),
		DPoPProof:           dpopProof,
	}

	if c.logger != nil {
		c.logger.Info("DPoP token validated successfully", "jkt", actualJKT)
	}

	return claims, dpopCtx, nil
}
