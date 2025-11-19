package validator

import (
	"errors"
	"strings"
)

var (
	// ErrExcessiveTokenDots is returned when a token contains too many dots,
	// which could indicate a malicious attempt to exploit CVE-2025-27144.
	ErrExcessiveTokenDots = errors.New("token contains excessive dots (possible DoS attack)")
)

const (
	// maxTokenDots is the maximum number of dots allowed in a JWT token.
	// Valid formats:
	// - JWS compact: header.payload.signature (2 dots)
	// - JWE compact: header.key.iv.ciphertext.tag (4 dots)
	// - JWE with multiple recipients: can have more sections
	// We allow up to 5 dots to be safe, which covers all valid use cases.
	maxTokenDots = 5
)

// validateTokenFormat performs pre-validation on the token string to protect
// against CVE-2025-27144 (memory exhaustion via excessive dots).
//
// This is a defense-in-depth measure for v2.x which uses go-jose v2.
// The underlying vulnerability is in go-jose v2's use of strings.Split()
// without limits. This function rejects obviously malicious inputs before
// they reach the vulnerable code.
//
// Note: This is a workaround, not a complete fix. The vulnerability is
// fully resolved in v3.x which uses lestrrat-go/jwx.
func validateTokenFormat(tokenString string) error {
	// Count dots in the token
	dotCount := strings.Count(tokenString, ".")
	
	if dotCount > maxTokenDots {
		return ErrExcessiveTokenDots
	}
	
	// Additional basic validation
	if len(tokenString) == 0 {
		return errors.New("token is empty")
	}
	
	// Reject tokens that are suspiciously large (> 1MB)
	// Valid JWTs should rarely exceed a few KB
	if len(tokenString) > 1024*1024 {
		return errors.New("token exceeds maximum size (1MB)")
	}
	
	return nil
}
