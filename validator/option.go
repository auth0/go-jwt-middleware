package validator

import (
	"time"
)

// Option is a function that configures a Validator.
type Option func(*Validator) error

// WithAllowedClockSkew is an option which sets up the allowed
// clock skew for the token. Note that in order to use this
// the expected claims Time field MUST not be time.IsZero().
// If this option is not used clock skew is not allowed.
func WithAllowedClockSkew(skew time.Duration) Option {
	return func(v *Validator) error {
		v.allowedClockSkew = skew
		return nil
	}
}

// WithCustomClaims sets up a function that returns the object
// CustomClaims that will be unmarshalled into and on which
// Validate is called on for custom validation. If this option
func WithCustomClaims(f func() CustomClaims) Option {
	return func(v *Validator) error {
		v.customClaims = f
		return nil
	}
}
