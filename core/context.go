package core

import "context"

// contextKey is an unexported type for context keys to prevent collisions.
// Using an unexported type ensures that only this package can create context keys,
// eliminating the risk of collisions with other packages.
type contextKey int

const (
	claimsKey contextKey = iota
	dpopContextKey
)

// GetClaims retrieves claims from the context with type safety using generics.
//
// This is a type-safe alternative to manually type-asserting the claims from the context.
// It returns an error if the claims are not found or if the type assertion fails.
//
// Example usage:
//
//	claims, err := core.GetClaims[*validator.ValidatedClaims](ctx)
//	if err != nil {
//	    return err
//	}
//	// Use claims...
func GetClaims[T any](ctx context.Context) (T, error) {
	var zero T

	val := ctx.Value(claimsKey)
	if val == nil {
		return zero, ErrClaimsNotFound
	}

	claims, ok := val.(T)
	if !ok {
		return zero, NewValidationError(
			ErrorCodeClaimsNotFound,
			"claims type assertion failed",
			nil,
		)
	}

	return claims, nil
}

// SetClaims stores claims in the context.
// This is a helper function for adapters to set claims after validation.
func SetClaims(ctx context.Context, claims any) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// HasClaims checks if claims exist in the context without retrieving them.
func HasClaims(ctx context.Context) bool {
	return ctx.Value(claimsKey) != nil
}

// SetDPoPContext stores DPoP context in the context.
// This is a helper function for adapters to set DPoP context after validation.
//
// DPoP context contains information about the validated DPoP proof, including
// the public key thumbprint, issued-at timestamp, and the raw proof JWT.
func SetDPoPContext(ctx context.Context, dpopCtx *DPoPContext) context.Context {
	return context.WithValue(ctx, dpopContextKey, dpopCtx)
}

// GetDPoPContext retrieves DPoP context from the context.
// Returns nil if no DPoP context exists (e.g., for Bearer tokens).
//
// Example usage:
//
//	dpopCtx := core.GetDPoPContext(ctx)
//	if dpopCtx != nil {
//	    log.Printf("DPoP token from key: %s", dpopCtx.PublicKeyThumbprint)
//	}
func GetDPoPContext(ctx context.Context) *DPoPContext {
	val := ctx.Value(dpopContextKey)
	if val == nil {
		return nil
	}

	dpopCtx, ok := val.(*DPoPContext)
	if !ok {
		return nil
	}

	return dpopCtx
}

// HasDPoPContext checks if a DPoP context exists in the context.
// Returns true for DPoP-bound tokens, false for Bearer tokens.
//
// Example usage:
//
//	if core.HasDPoPContext(ctx) {
//	    dpopCtx := core.GetDPoPContext(ctx)
//	    // Handle DPoP-specific logic...
//	}
func HasDPoPContext(ctx context.Context) bool {
	return ctx.Value(dpopContextKey) != nil
}
