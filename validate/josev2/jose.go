package josev2

import (
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type CustomClaims interface {
	Validate() error
}

type Option func(*Validator)

func WithAllowedClockSkew(skew time.Duration) Option {
	return func(v *Validator) {
		v.allowedClockSkew = skew
	}
}

func WithCustomClaims(f func() CustomClaims) Option {
	return func(v *Validator) {
		v.customClaims = f
	}
}

func New(keyFunc func() (interface{}, error),
	signatureAlgorithm jose.SignatureAlgorithm,
	expectedClaims func() jwt.Expected,
	opts ...Option) *Validator {

	// TODO(joncarl): error on nil keyFunc and expectedClaims as we want to
	// require them

	v := &Validator{
		allowedClockSkew:   0,
		keyFunc:            keyFunc,
		signatureAlgorithm: signatureAlgorithm,
		customClaims:       nil,
		expectedClaims:     expectedClaims,
	}

	for _, opt := range opts {
		opt(v)
	}

	return v
}

type Validator struct {
	// required options
	keyFunc            func() (interface{}, error)
	signatureAlgorithm jose.SignatureAlgorithm
	expectedClaims     func() jwt.Expected

	// optional options
	allowedClockSkew time.Duration
	customClaims     func() CustomClaims
}

// ValidateToken validates the passed in JWT using the jose v2 package.
func (v *Validator) ValidateToken(token string) (interface{}, error) {
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

	key, err := v.keyFunc()
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

	if err = claimDest[0].(*jwt.Claims).ValidateWithLeeway(v.expectedClaims(), v.allowedClockSkew); err != nil {
		return nil, fmt.Errorf("expected claims not validated: %w", err)
	}

	if v.customClaims != nil {
		if err = claimDest[1].(CustomClaims).Validate(); err != nil {
			return nil, fmt.Errorf("custom claims not validated: %w", err)
		}
	}

	return tok, nil
}
