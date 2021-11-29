package validator

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Validator to use with the jose v2 package.
type Validator struct {
	keyFunc            func(context.Context) (interface{}, error) // Required.
	signatureAlgorithm jose.SignatureAlgorithm                    // Required.
	expectedClaims     jwt.Expected                               // Optional.
	customClaims       CustomClaims                               // Optional.
	allowedClockSkew   time.Duration                              // Optional.
}

// ValidatedClaims is the struct that will be inserted into
// the context for the user. CustomClaims will be nil
// unless WithCustomClaims is passed to New.
type ValidatedClaims struct {
	CustomClaims     CustomClaims
	RegisteredClaims jwt.Claims
}

// New sets up a new Validator with the required keyFunc
// and signatureAlgorithm as well as custom options.
func New(
	keyFunc func(context.Context) (interface{}, error),
	signatureAlgorithm string,
	issuerURL string,
	audience []string,
	opts ...Option,
) (*Validator, error) {
	if keyFunc == nil {
		return nil, errors.New("keyFunc is required but was nil")
	}
	if signatureAlgorithm == "" {
		return nil, errors.New("signature algorithm is required but was empty")
	}
	if issuerURL == "" {
		return nil, errors.New("issuer url is required but was empty")
	}
	if audience == nil {
		return nil, errors.New("audience is required but was nil")
	}

	v := &Validator{
		keyFunc:            keyFunc,
		signatureAlgorithm: jose.SignatureAlgorithm(signatureAlgorithm),
		expectedClaims: jwt.Expected{
			Issuer:   issuerURL,
			Audience: audience,
			Time:     time.Now(),
		},
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

// ValidateToken validates the passed in JWT using the jose v2 package.
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (interface{}, error) {
	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return nil, fmt.Errorf("could not parse the token: %w", err)
	}

	if string(v.signatureAlgorithm) != token.Headers[0].Algorithm {
		return nil, fmt.Errorf(
			"expected %q signing algorithm but token specified %q",
			v.signatureAlgorithm,
			token.Headers[0].Algorithm,
		)
	}

	key, err := v.keyFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting the keys from the key func: %w", err)
	}

	claimDest := []interface{}{&jwt.Claims{}}
	if v.customClaims != nil {
		claimDest = append(claimDest, v.customClaims)
	}

	if err = token.Claims(key, claimDest...); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}

	userCtx := &ValidatedClaims{
		RegisteredClaims: *claimDest[0].(*jwt.Claims),
	}

	if err = userCtx.RegisteredClaims.ValidateWithLeeway(v.expectedClaims, v.allowedClockSkew); err != nil {
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
