package main

import (
	"context"
	"errors"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/go-kit/kit/endpoint"
	"net/url"
	"time"
)

const (
	ExampleAuth0Audience = "api.audience"
)

// getJWTValidator validates a JWT similar to the package CheckJWT method.
func getJWTValidator(iss string) (*validator.Validator, error) {
	issuer, err := url.Parse(iss)
	if err != nil {
		return nil, err
	}

	provider := jwks.NewCachingProvider(issuer, 5*time.Minute)
	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuer.String(),
		[]string{ExampleAuth0Audience},
	)
	if err != nil {
		return nil, err
	}

	return jwtValidator, nil
}

// TokenValidator is a go-kit endpoint-level middleware to validate a JWT issued from Auth0.
func TokenValidator(iss string) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			accessToken, ok := ctx.Value("access_token").(string)
			if !ok {
				return nil, errors.New("no token found")
			}

			valid8r, err := getJWTValidator(iss)
			if err != nil {
				return nil, errors.New("cannot get JWT validator")
			}

			_, err = valid8r.ValidateToken(ctx, accessToken)
			if err != nil {
				return nil, errors.New("cannot validate token (unauthenticated)")
			}

			return next(ctx, request)
		}
	}
}
