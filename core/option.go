package core

import (
	"errors"
	"time"
)

// Option is a function that configures the Core.
// Options return errors to enable validation during construction.
type Option func(*Core) error

// New creates a new Core instance with the provided options.
//
// The Core must be configured with at least a TokenValidator using WithValidator.
// All other options are optional and will use sensible defaults if not provided.
//
// Example:
//
//	core, err := core.New(
//	    core.WithValidator(validator),
//	    core.WithCredentialsOptional(true),
//	    core.WithLogger(logger),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
func New(opts ...Option) (*Core, error) {
	c := &Core{
		credentialsOptional: false, // Secure default: require credentials
		dpopMode:            DPoPAllowed,
		dpopProofOffset:     300 * time.Second, // Default: 300s (5 minutes) max age for DPoP proofs
		dpopIATLeeway:       30 * time.Second,  // Default: 30s clock skew allowance
	}

	// Apply all options
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	// Validate required configuration
	if err := c.validate(); err != nil {
		return nil, err
	}

	return c, nil
}

// validate ensures all required fields are set.
func (c *Core) validate() error {
	if c.validator == nil {
		return NewValidationError(
			ErrorCodeValidatorNotSet,
			"validator is required but not set (use WithValidator option)",
			nil,
		)
	}
	return nil
}

// WithValidator sets the validator for the Core.
// This is a required option. The validator must implement both ValidateToken
// and ValidateDPoPProof methods.
func WithValidator(validator Validator) Option {
	return func(c *Core) error {
		if validator == nil {
			return errors.New("validator cannot be nil")
		}
		c.validator = validator
		return nil
	}
}

// WithCredentialsOptional configures whether credentials are optional.
//
// When set to true, requests without tokens will be allowed to proceed
// without validation. The claims will be nil in the context.
//
// When set to false (default), requests without tokens will return ErrJWTMissing.
//
// Use this option carefully - requiring authentication by default is more secure.
func WithCredentialsOptional(optional bool) Option {
	return func(c *Core) error {
		c.credentialsOptional = optional
		return nil
	}
}

// WithLogger sets an optional logger for the Core.
//
// When configured, the Core will log debug information about token
// extraction, validation success/failure, and timing information.
//
// If you need custom metrics or callbacks, consider wrapping the Core
// in your own implementation that delegates to the Core for validation.
//
// Example:
//
//	logger := slog.Default()
//	core, _ := core.New(
//	    core.WithValidator(validator),
//	    core.WithLogger(logger),
//	)
func WithLogger(logger Logger) Option {
	return func(c *Core) error {
		if logger == nil {
			return errors.New("logger cannot be nil")
		}
		c.logger = logger
		return nil
	}
}

// WithDPoPMode configures the DPoP operational mode.
//
// Modes:
//   - DPoPAllowed (default): Accept both Bearer and DPoP tokens
//   - DPoPRequired: Only accept DPoP tokens, reject Bearer tokens
//   - DPoPDisabled: Only accept Bearer tokens, ignore DPoP headers
//
// Example:
//
//	core, _ := core.New(
//	    core.WithValidator(validator),
//	    core.WithDPoPMode(core.DPoPRequired),
//	)
func WithDPoPMode(mode DPoPMode) Option {
	return func(c *Core) error {
		c.dpopMode = mode
		return nil
	}
}

// WithDPoPProofOffset sets the maximum age offset for DPoP proofs.
// This determines how far in the past a DPoP proof's iat timestamp can be.
//
// Default: 300 seconds (5 minutes)
//
// Use a shorter duration for high-security environments:
//
//	core, _ := core.New(
//	    core.WithValidator(validator),
//	    core.WithDPoPProofOffset(60 * time.Second), // Stricter: 60s
//	)
func WithDPoPProofOffset(offset time.Duration) Option {
	return func(c *Core) error {
		if offset < 0 {
			return errors.New("DPoP proof offset cannot be negative")
		}
		c.dpopProofOffset = offset
		return nil
	}
}

// WithDPoPIATLeeway sets the clock skew allowance for future iat claims in DPoP proofs.
// This allows DPoP proofs with iat timestamps slightly in the future due to clock drift.
//
// Default: 5 seconds
//
// Increase this if you expect more clock skew:
//
//	core, _ := core.New(
//	    core.WithValidator(validator),
//	    core.WithDPoPIATLeeway(30 * time.Second), // More lenient: 30s
//	)
func WithDPoPIATLeeway(leeway time.Duration) Option {
	return func(c *Core) error {
		if leeway < 0 {
			return errors.New("DPoP IAT leeway cannot be negative")
		}
		c.dpopIATLeeway = leeway
		return nil
	}
}
