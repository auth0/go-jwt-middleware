package core

import "context"

// contextKey is an unexported type for context keys to prevent collisions.
// Using an unexported type ensures that only this package can create context keys,
// eliminating the risk of collisions with other packages.
type contextKey int

const (
	claimsKey contextKey = iota
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
