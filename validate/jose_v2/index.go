package jose_v2

import (
	"errors"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

type CustomClaims interface {
	Validate() error
}

type Validator struct {
	// TODO(joncarl): set this to 0 by default
	AllowedClockSkew time.Duration
	KeyFunc          func() interface{}
	SigningAlgorithm string
	CustomClaims     func() CustomClaims
	// TODO(joncarl): maybe this can be an object instead of func?
	ExpectedClaims func() jwt.Expected
}

// what should this do at a base level?
// - [X] parse
// - [X] provide key getter
// - [X] make sure signing method == alg header - maybe allow for no signing method?
// - [X] custom checks for validation
// - [X] support clock skew
// - [X] custom claims
// - [ ] maybe some function to later understand the user info from context?

func (v *Validator) ValidateToken(token string) (interface{}, error) {
	// parse
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		// TODO(joncarl): wrap the error?
		return nil, err
	}

	// make sure signing method == alg header
	// TODO(joncarl): we need to figure out how to best handle this.
	// for now we are taking the first header / signature and comparing
	// the alg there. I think the simplest thing to do is not support multi
	// recipient JWT.
	if len(tok.Headers) == 0 {
		return nil, errors.New("no headers!")
	}
	if v.SigningAlgorithm != "" && v.SigningAlgorithm != tok.Headers[0].Algorithm {
		return nil, fmt.Errorf("expected %q signin algorithm but token specified %q", v.SigningAlgorithm, tok.Headers[0].Algorithm)
	}

	// get key
	jwks := v.KeyFunc()

	claimDest := []interface{}{&jwt.Claims{}}
	if v.CustomClaims != nil {
		claimDest = append(claimDest, v.CustomClaims())
	}

	if err = tok.Claims(jwks, claimDest...); err != nil {
		return nil, fmt.Errorf("could not get token claims: %w", err)
	}

	// check claims
	if err = claimDest[0].(*jwt.Claims).ValidateWithLeeway(v.ExpectedClaims(), v.AllowedClockSkew); err != nil {
		return nil, err
	}

	// custom validation
	if v.CustomClaims != nil {
		if err = claimDest[1].(CustomClaims).Validate(); err != nil {
			return nil, err
		}
	}

	return tok, nil
}
