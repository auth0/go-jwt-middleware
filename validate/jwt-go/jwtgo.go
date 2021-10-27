package jwtgo

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

// CustomClaims defines any custom data / claims wanted. The validator will
// call the Validate function which is where custom validation logic can be
// defined.
type CustomClaims interface {
	jwt.Claims
	Validate(context.Context) error
}

// Option is how options for the validator are setup.
type Option func(*validator)

// WithCustomClaims sets up a function that returns the object CustomClaims are
// unmarshalled into and the object which Validate is called on for custom
// validation. If this option is not used the validator will do nothing for
// custom claims.
func WithCustomClaims(f func() CustomClaims) Option {
	return func(v *validator) {
		v.customClaims = f
	}
}

// New sets up a new Validator. With the required keyFunc and
// signatureAlgorithm as well as options.
func New(
	keyFunc jwt.Keyfunc,
	signatureAlgorithm string,
	opts ...Option,
) (*validator, error) {
	if keyFunc == nil {
		return nil, errors.New("keyFunc is required but was nil")
	}

	v := &validator{
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		customClaims:       nil,
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

type validator struct {
	// required options
	keyFunc            func(*jwt.Token) (interface{}, error)
	signatureAlgorithm string

	// optional options
	customClaims func() CustomClaims
}

// ValidateToken validates the passed in JWT using the jwt-go package.
func (v *validator) ValidateToken(ctx context.Context, token string) (interface{}, error) {
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
