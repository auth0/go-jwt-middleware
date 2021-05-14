package josev2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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
	Claims       jwt.Claims
}

// Option is how options for the validator are setup.
type Option func(*Validator)

// WithAllowedClockSkew is an option which sets up the allowed clock skew for
// the token. Note that in order to use this the expected claims Time field
// MUST not be time.IsZero(). If this option is not used clock skew is not
// allowed.
func WithAllowedClockSkew(skew time.Duration) Option {
	return func(v *Validator) {
		v.allowedClockSkew = skew
	}
}

// WithCustomClaims sets up a function that returns the object CustomClaims are
// unmarshalled into and the object which Validate is called on for custom
// validation. If this option is not used the validator will do nothing for
// custom claims.
func WithCustomClaims(f func() CustomClaims) Option {
	return func(v *Validator) {
		v.customClaims = f
	}
}

// WithExpectedClaims sets up a function that returns the object used to
// validate claims. If this option is not used a default jwt.Expected object is
// used which only validates token time.
func WithExpectedClaims(f func() jwt.Expected) Option {
	return func(v *Validator) {
		v.expectedClaims = f
	}
}

// New sets up a new Validator. With the required keyFunc and
// signatureAlgorithm as well as options.
func New(keyFunc func(context.Context) (interface{}, error),
	signatureAlgorithm jose.SignatureAlgorithm,
	opts ...Option) (*Validator, error) {

	if keyFunc == nil {
		return nil, errors.New("keyFunc is required but was nil")
	}

	v := &Validator{
		allowedClockSkew:   0,
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		customClaims:       nil,
		expectedClaims: func() jwt.Expected {
			return jwt.Expected{
				Time: time.Now(),
			}
		},
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

type Validator struct {
	// required options
	keyFunc            func(context.Context) (interface{}, error)
	signatureAlgorithm jose.SignatureAlgorithm

	// optional options which we will default if not specified
	expectedClaims   func() jwt.Expected
	allowedClockSkew time.Duration
	customClaims     func() CustomClaims
}

// ValidateToken validates the passed in JWT using the jose v2 package.
func (v *Validator) ValidateToken(ctx context.Context, token string) (interface{}, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("could not parse the token: %w", err)
	}

	signatureAlgorithm := string(v.signatureAlgorithm)

	// if jwt.ParseSigned did not error there will always be at least one
	// header in the token
	if signatureAlgorithm != "" && signatureAlgorithm != tok.Headers[0].Algorithm {
		return nil, fmt.Errorf("expected %q signin algorithm but token specified %q", signatureAlgorithm, tok.Headers[0].Algorithm)
	}

	key, err := v.keyFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting the keys from the key func: %w", err)
	}

	claimDest := []interface{}{&jwt.Claims{}}
	if v.customClaims != nil {
		claimDest = append(claimDest, v.customClaims())
	}

	if err = tok.Claims(key, claimDest...); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}

	userCtx := &UserContext{
		Claims: *claimDest[0].(*jwt.Claims),
	}

	if err = userCtx.Claims.ValidateWithLeeway(v.expectedClaims(), v.allowedClockSkew); err != nil {
		return nil, fmt.Errorf("expected claims not validated: %w", err)
	}

	if v.customClaims != nil {
		userCtx.CustomClaims = claimDest[1].(CustomClaims)
		if err = userCtx.CustomClaims.Validate(ctx); err != nil {
			return nil, fmt.Errorf("custom claims not validated: %w", err)
		}
	}

	return userCtx, nil
}
