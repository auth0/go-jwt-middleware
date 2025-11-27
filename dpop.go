package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/auth0/go-jwt-middleware/v3/core"
)

// DPoPMode represents the operational mode for DPoP token validation.
type DPoPMode = core.DPoPMode

const (
	// DPoPAllowed accepts both Bearer and DPoP tokens (default, non-breaking).
	// This mode allows gradual migration from Bearer to DPoP tokens.
	DPoPAllowed DPoPMode = core.DPoPAllowed

	// DPoPRequired only accepts DPoP tokens and rejects Bearer tokens.
	// Use this mode when all clients have been upgraded to support DPoP.
	DPoPRequired DPoPMode = core.DPoPRequired

	// DPoPDisabled only accepts Bearer tokens and ignores DPoP headers.
	// Use this mode to explicitly opt-out of DPoP support.
	DPoPDisabled DPoPMode = core.DPoPDisabled
)

// DPoPHeaderExtractor extracts the DPoP proof from the "DPoP" HTTP header.
// Returns empty string if the header is not present (which is valid for Bearer tokens).
// Returns an error if multiple DPoP headers are present (per RFC 9449).
func DPoPHeaderExtractor(r *http.Request) (string, error) {
	headers := r.Header.Values("DPoP")

	// No DPoP header is valid (Bearer token flow)
	if len(headers) == 0 {
		return "", nil
	}

	// Multiple DPoP headers are not allowed per RFC 9449
	if len(headers) > 1 {
		return "", fmt.Errorf("multiple DPoP headers are not allowed")
	}

	return headers[0], nil
}

// GetDPoPContext retrieves the DPoP context from the request context.
// Returns nil if no DPoP context exists (e.g., for Bearer tokens).
//
// This is a convenience wrapper around core.GetDPoPContext for use in HTTP handlers.
//
// Example:
//
//	dpopCtx := jwtmiddleware.GetDPoPContext(r.Context())
//	if dpopCtx != nil {
//	    log.Printf("DPoP token from key: %s", dpopCtx.PublicKeyThumbprint)
//	}
func GetDPoPContext(ctx context.Context) *core.DPoPContext {
	return core.GetDPoPContext(ctx)
}

// HasDPoPContext checks if a DPoP context exists in the request context.
// Returns true for DPoP-bound tokens, false for Bearer tokens.
//
// This is a convenience wrapper around core.HasDPoPContext for use in HTTP handlers.
//
// Example:
//
//	if jwtmiddleware.HasDPoPContext(r.Context()) {
//	    dpopCtx := jwtmiddleware.GetDPoPContext(r.Context())
//	    // Handle DPoP-specific logic...
//	}
func HasDPoPContext(ctx context.Context) bool {
	return core.HasDPoPContext(ctx)
}
