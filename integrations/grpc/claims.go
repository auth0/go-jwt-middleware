package grpc

import (
	"context"

	"github.com/auth0/go-jwt-middleware/v3/core"
)

// GetClaims retrieves claims from the context with type safety using generics.
//
// This is a type-safe alternative to manually type-asserting the claims from the context.
// It returns an error if the claims are not found or if the type assertion fails.
//
// Example:
//
//	claims, err := jwtgrpc.GetClaims[*validator.ValidatedClaims](ctx)
//	if err != nil {
//	    return nil, status.Error(codes.Internal, "failed to get claims")
//	}
//	fmt.Println(claims.RegisteredClaims.Subject)
func GetClaims[T any](ctx context.Context) (T, error) {
	return core.GetClaims[T](ctx)
}

// MustGetClaims retrieves claims from the context or panics.
//
// SAFETY: Only use this function when you are certain claims exist in the context:
//   - After the JWT interceptor has successfully validated a token
//   - When credentialsOptional is false (default), ensuring all requests have valid tokens
//   - In methods that are NOT in the excluded methods list
//
// For methods where credentials might be optional, use GetClaims instead and handle the error.
//
// Example:
//
//	claims := jwtgrpc.MustGetClaims[*validator.ValidatedClaims](ctx)
//	fmt.Println(claims.RegisteredClaims.Subject)
func MustGetClaims[T any](ctx context.Context) T {
	claims, err := core.GetClaims[T](ctx)
	if err != nil {
		panic(err)
	}
	return claims
}

// HasClaims checks if claims exist in the context.
//
// Example:
//
//	if jwtgrpc.HasClaims(ctx) {
//	    claims, _ := jwtgrpc.GetClaims[*validator.ValidatedClaims](ctx)
//	    // Use claims...
//	}
func HasClaims(ctx context.Context) bool {
	return core.HasClaims(ctx)
}
