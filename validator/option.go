package validator

import (
	"github.com/go-jose/go-jose/v4/jwt"
	"time"
)

// Option is how options for the Validator are set up.
type Option func(*Validator)

// WithAllowedClockSkew is an option which sets up the allowed
// clock skew for the token. Note that in order to use this
// the expected claims Time field MUST not be time.IsZero().
// If this option is not used clock skew is not allowed.
func WithAllowedClockSkew(skew time.Duration) Option {
	return func(v *Validator) {
		v.allowedClockSkew = skew
	}
}

// WithCustomClaims sets up a function that returns the object
// CustomClaims that will be unmarshalled into and on which
// Validate is called on for custom validation. If this option
// is not used the Validator will do nothing for custom claims.
func WithCustomClaims(f func() CustomClaims) Option {
	return func(v *Validator) {
		v.customClaims = f
	}
}

// WithExpectedClaims allows fine-grained customization of the expected claims
func WithExpectedClaims(expectedClaims ...jwt.Expected) Option {
	return func(v *Validator) {
		if len(expectedClaims) == 0 {
			return
		}
		if v.expectedClaims == nil {
			v.expectedClaims = make([]jwt.Expected, 0)
		}
		v.expectedClaims = append(v.expectedClaims, expectedClaims...)
	}
}
