package jwtgo

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

// Validator to use with the jwt-go package.
type Validator struct {
	keyFunc            func(*jwt.Token) (interface{}, error) // Required.
	signatureAlgorithm string                                // Required.
	customClaims       func() CustomClaims                   // Optional.
}

// Option is how options for the Validator are set up.
type Option func(*Validator)

// CustomClaims defines any custom data / claims wanted.
// The Validator will call the Validate function which
// is where custom validation logic can be defined.
type CustomClaims interface {
	jwt.Claims
	Validate(context.Context) error
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

// New sets up a new Validator with the required keyFunc
// and signatureAlgorithm as well as custom options.
func New(
	keyFunc jwt.Keyfunc,
	signatureAlgorithm string,
	opts ...Option,
) (*Validator, error) {
	if keyFunc == nil {
		return nil, errors.New("keyFunc is required but was nil")
	}

	v := &Validator{
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		customClaims:       nil,
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

// ValidateToken validates the passed in JWT using the jwt-go package.
func (v *Validator) ValidateToken(ctx context.Context, token string) (interface{}, error) {
	var claims jwt.Claims = &jwt.RegisteredClaims{}
	if v.customClaims != nil {
		claims = v.customClaims()
	}

	parser := &jwt.Parser{}
	if v.signatureAlgorithm != "" {
		parser.ValidMethods = []string{v.signatureAlgorithm}
	}

	if _, err := parser.ParseWithClaims(token, claims, v.keyFunc); err != nil {
		return nil, fmt.Errorf("could not parse the token: %w", err)
	}

	if customClaims, ok := claims.(CustomClaims); ok {
		if err := customClaims.Validate(ctx); err != nil {
			return nil, fmt.Errorf("custom claims not validated: %w", err)
		}
	}

	return claims, nil
}
