package validator

import (
	"context"
	"fmt"
	"time"
)

// WithKeyFunc returns an option that configures the key function for token validation.
// This is a required option.
func WithKeyFunc(keyFunc func(context.Context) (interface{}, error)) Option {
	return func(v *Validator) error {
		if keyFunc == nil {
			return ErrKeyFuncRequired
		}
		v.keyFunc = keyFunc
		return nil
	}
}

// WithSignatureAlgorithm returns an option that configures the signature algorithm.
// This is a required option.
func WithSignatureAlgorithm(algorithm SignatureAlgorithm) Option {
	return func(v *Validator) error {
		if algorithm == "" {
			return ErrSignatureAlgRequired
		}
		if _, ok := jwaAlgorithms[algorithm]; !ok {
			return ErrUnsupportedAlgorithm
		}
		v.signatureAlgorithm = algorithm
		return nil
	}
}

// WithIssuer returns an option that adds a single issuer to the list of expected issuers.
func WithIssuer(issuer string) Option {
	return func(v *Validator) error {
		if issuer == "" {
			return fmt.Errorf("issuer cannot be empty")
		}
		v.expectedIssuers = append(v.expectedIssuers, issuer)
		return nil
	}
}

// WithIssuers returns an option that adds multiple issuers to the list of expected issuers.
func WithIssuers(issuers ...string) Option {
	return func(v *Validator) error {
		if len(issuers) == 0 {
			return fmt.Errorf("issuers list cannot be empty")
		}
		for _, issuer := range issuers {
			if issuer == "" {
				return fmt.Errorf("issuer cannot be empty")
			}
		}
		v.expectedIssuers = append(v.expectedIssuers, issuers...)
		return nil
	}
}

// WithAudience returns an option that adds a single audience to the list of expected audiences.
func WithAudience(audience string) Option {
	return func(v *Validator) error {
		if audience == "" {
			return fmt.Errorf("audience cannot be empty")
		}
		v.expectedAudience = append(v.expectedAudience, audience)
		return nil
	}
}

// WithAudiences returns an option that adds multiple audiences to the list of expected audiences.
func WithAudiences(audiences ...string) Option {
	return func(v *Validator) error {
		if len(audiences) == 0 {
			return fmt.Errorf("audiences list cannot be empty")
		}
		for _, aud := range audiences {
			if aud == "" {
				return fmt.Errorf("audience cannot be empty")
			}
		}
		v.expectedAudience = append(v.expectedAudience, audiences...)
		return nil
	}
}

// WithAllowedClockSkew is an option which sets up the allowed
// clock skew for the token validation.
func WithAllowedClockSkew(skew time.Duration) Option {
	return func(v *Validator) error {
		if skew < 0 {
			return fmt.Errorf("clock skew cannot be negative")
		}
		v.allowedClockSkew = skew
		return nil
	}
}

// WithCustomClaims sets up a function that returns the object
// CustomClaims that will be unmarshalled into and on which
// Validate is called on for custom validation.
func WithCustomClaims(f func() CustomClaims) Option {
	return func(v *Validator) error {
		if f == nil {
			return fmt.Errorf("custom claims function cannot be nil")
		}
		v.customClaims = f
		return nil
	}
}

// WithSkipIssuerValidation configures the validator to skip issuer validation.
// This should be used with caution as it bypasses a security check.
func WithSkipIssuerValidation() Option {
	return func(v *Validator) error {
		v.skipIssuerValidation = true
		return nil
	}
}

// WithReplaceIssuers returns an option that replaces all currently configured
// issuers with the provided ones.
func WithReplaceIssuers(issuers []string) Option {
	return func(v *Validator) error {
		if len(issuers) == 0 {
			return ErrIssuerURLRequired
		}
		// Replace existing issuers
		v.expectedIssuers = issuers
		return nil
	}
}

// WithReplaceAudiences returns an option that replaces all currently configured
// audiences with the provided ones.
func WithReplaceAudiences(audiences []string) Option {
	return func(v *Validator) error {
		if len(audiences) == 0 {
			return ErrAudienceRequired
		}
		for _, aud := range audiences {
			if aud == "" {
				return fmt.Errorf("audience cannot be empty")
			}
		}
		v.expectedAudience = audiences
		return nil
	}
}

// WithExpectedIssuers is an alias for WithReplaceIssuers for backward compatibility
func WithExpectedIssuers(issuers []string) Option {
	return WithReplaceIssuers(issuers)
}

// WithAdditionalIssuers is an alias for WithIssuers for backward compatibility
func WithAdditionalIssuers(additionalIssuers []string) Option {
	if len(additionalIssuers) == 0 {
		return func(v *Validator) error {
			return nil // No issuers to add, just return without error
		}
	}
	return WithIssuers(additionalIssuers...)
}
