package josev2

import (
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
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
func WithCustomClaims(c CustomClaims) Option {
	return func(v *Validator) {
		v.customClaims = c
	}
}
