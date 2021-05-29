package jwtgo

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt"
)

// CustomClaims defines any custom data / claims wanted. The validator will
// call the Validate function which is where custom validation logic can be
// defined.
type CustomClaims interface {
	Validate(context.Context) error
}

// UserContext is the struct that will be inserted into the context for the
// user. CustomClaims will be nil unless WithCustomClaims is passed to New.
type UserContext struct {
	CustomClaims CustomClaims
	jwt.StandardClaims
}

// Option is how options for the validator are setup.
type Option func(*validator)

// New sets up a new Validator. With the required keyFunc and
// signatureAlgorithm as well as options.
func New(keyFunc jwt.Keyfunc,
	signatureAlgorithm string,
	opts ...Option) (*validator, error) {

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

	customClaims func() CustomClaims
}

// ValidateToken validates the passed in JWT using the jose v2 package.
func (v *validator) ValidateToken(ctx context.Context, token string) (interface{}, error) {
	userCtx := UserContext{}

	p := new(jwt.Parser)

	p.ValidMethods = []string{v.signatureAlgorithm}

	tok, err := jwt.ParseWithClaims(token, &userCtx, v.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("could not parse the token: %w", err)
	}

	fmt.Printf("token: %+v", tok)

	return &userCtx, nil
}
