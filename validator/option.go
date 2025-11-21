package validator

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Option is how options for the Validator are set up.
// Options return errors to enable validation during construction.
type Option func(*Validator) error

// WithKeyFunc sets the function that provides the key for token verification.
// This is a required option.
//
// The keyFunc is called during token validation to retrieve the key(s) used
// to verify the token signature. For JWKS-based validation, use jwks.Provider.KeyFunc.
func WithKeyFunc(keyFunc func(context.Context) (any, error)) Option {
	return func(v *Validator) error {
		if keyFunc == nil {
			return errors.New("keyFunc cannot be nil")
		}
		v.keyFunc = keyFunc
		return nil
	}
}

// WithAlgorithm sets the signature algorithm that tokens must use.
// This is a required option.
//
// Supported algorithms: RS256, RS384, RS512, ES256, ES384, ES512,
// PS256, PS384, PS512, HS256, HS384, HS512, EdDSA.
func WithAlgorithm(algorithm SignatureAlgorithm) Option {
	return func(v *Validator) error {
		if _, ok := allowedSigningAlgorithms[algorithm]; !ok {
			return fmt.Errorf("unsupported signature algorithm: %s", algorithm)
		}
		v.signatureAlgorithm = algorithm
		return nil
	}
}

// WithIssuer sets a single expected issuer claim (iss) for token validation.
// This is a required option (use either WithIssuer or WithIssuers, not both).
//
// The issuer URL should match the iss claim in the JWT. Tokens with a
// different issuer will be rejected.
func WithIssuer(issuerURL string) Option {
	return func(v *Validator) error {
		if issuerURL == "" {
			return errors.New("issuer cannot be empty")
		}
		// Optional: Validate URL format
		if _, err := url.Parse(issuerURL); err != nil {
			return fmt.Errorf("invalid issuer URL: %w", err)
		}
		v.expectedIssuers = []string{issuerURL}
		return nil
	}
}

// WithIssuers sets multiple expected issuer claims (iss) for token validation.
// This is a required option (use either WithIssuer or WithIssuers, not both).
//
// The token must contain one of the specified issuers. Tokens without
// any matching issuer will be rejected.
func WithIssuers(issuers []string) Option {
	return func(v *Validator) error {
		if len(issuers) == 0 {
			return errors.New("issuers cannot be empty")
		}
		for i, iss := range issuers {
			if iss == "" {
				return fmt.Errorf("issuer at index %d cannot be empty", i)
			}
		}
		v.expectedIssuers = issuers
		return nil
	}
}

// WithAudience sets a single expected audience claim (aud) for token validation.
// This is a required option (use either WithAudience or WithAudiences, not both).
//
// The audience should match one of the aud claims in the JWT. Tokens without
// a matching audience will be rejected.
func WithAudience(audience string) Option {
	return func(v *Validator) error {
		if audience == "" {
			return errors.New("audience cannot be empty")
		}
		v.expectedAudiences = []string{audience}
		return nil
	}
}

// WithAudiences sets multiple expected audience claims (aud) for token validation.
// This is a required option (use either WithAudience or WithAudiences, not both).
//
// The token must contain at least one of the specified audiences. Tokens without
// any matching audience will be rejected.
func WithAudiences(audiences []string) Option {
	return func(v *Validator) error {
		if len(audiences) == 0 {
			return errors.New("audiences cannot be empty")
		}
		for i, aud := range audiences {
			if aud == "" {
				return fmt.Errorf("audience at index %d cannot be empty", i)
			}
		}
		v.expectedAudiences = audiences
		return nil
	}
}

// WithAllowedClockSkew sets the allowed clock skew for time-based claims.
//
// This allows for some tolerance when validating exp, nbf, and iat claims
// to account for clock differences between systems. If not set, the default
// is 0 (no clock skew allowed).
func WithAllowedClockSkew(skew time.Duration) Option {
	return func(v *Validator) error {
		if skew < 0 {
			return errors.New("clock skew cannot be negative")
		}
		v.allowedClockSkew = skew
		return nil
	}
}

// WithCustomClaims sets a function that returns a CustomClaims object
// for unmarshalling and validation.
//
// The function is called during construction to validate it returns a non-nil
// value, and then called for each token validation to create a new instance.
//
// Using generics allows you to return your concrete claims type directly
// without needing to explicitly cast to the CustomClaims interface.
//
// IMPORTANT: The function must be:
//   - Thread-safe (called concurrently by multiple requests)
//   - Idempotent (returns a new instance each time, no shared state)
//   - Fast (called on every token validation)
//   - Panic-free (panics will crash the request handler)
//
// Example:
//
//	validator.New(
//	    // ... other options
//	    validator.WithCustomClaims(func() *MyClaims {
//	        return &MyClaims{}  // No interface cast needed
//	    }),
//	)
func WithCustomClaims[T CustomClaims](f func() T) Option {
	return func(v *Validator) error {
		if f == nil {
			return errors.New("custom claims function cannot be nil")
		}

		// Wrap to return interface type for internal storage
		// Note: The function can return nil at runtime for conditional custom claims,
		// which is handled by customClaimsExist() during validation
		v.customClaims = func() CustomClaims {
			return f()
		}

		return nil
	}
}
