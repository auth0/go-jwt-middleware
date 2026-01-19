package validator

import (
	"context"
)

// ValidatedClaims is the struct that will be inserted into
// the context for the user. CustomClaims will be nil
// unless WithCustomClaims is passed to New.
type ValidatedClaims struct {
	CustomClaims     CustomClaims
	RegisteredClaims RegisteredClaims

	// ConfirmationClaim contains the cnf claim for DPoP binding (RFC 7800, RFC 9449).
	// This field will be nil for Bearer tokens and populated for DPoP tokens.
	ConfirmationClaim *ConfirmationClaim `json:"cnf,omitempty"`
}

// RegisteredClaims represents public claim
// values (as specified in RFC 7519).
type RegisteredClaims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Expiry    int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`
}

// CustomClaims defines any custom data / claims wanted.
// The Validator will call the Validate function which
// is where custom validation logic can be defined.
type CustomClaims interface {
	Validate(context.Context) error
}

// ConfirmationClaim represents the cnf (confirmation) claim per RFC 7800 and RFC 9449.
// It contains the JWK SHA-256 thumbprint that binds the access token to a specific key pair.
// This is used for DPoP (Demonstrating Proof-of-Possession) token binding.
type ConfirmationClaim struct {
	// JKT is the JWK SHA-256 Thumbprint (base64url-encoded).
	// This thumbprint must match the JKT calculated from the DPoP proof's JWK.
	JKT string `json:"jkt"`
}

// GetConfirmationJKT returns the jkt from the cnf claim, or empty string if not present.
// This method implements the core.TokenClaims interface.
func (v *ValidatedClaims) GetConfirmationJKT() string {
	if v.ConfirmationClaim == nil {
		return ""
	}
	return v.ConfirmationClaim.JKT
}

// HasConfirmation returns true if the token has a cnf claim.
// This method implements the core.TokenClaims interface.
func (v *ValidatedClaims) HasConfirmation() bool {
	return v.ConfirmationClaim != nil && v.ConfirmationClaim.JKT != ""
}
