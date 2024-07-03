package validator

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testClaims struct {
	Scope       string `json:"scope"`
	ReturnError error
}

func (tc *testClaims) Validate(context.Context) error {
	return tc.ReturnError
}

func TestValidator_ValidateToken(t *testing.T) {
	const (
		issuer   = "https://go-jwt-middleware.eu.auth0.com/"
		audience = "https://go-jwt-middleware-api/"
		subject  = "1234567890"
	)

	testCases := []struct {
		name           string
		token          string
		keyFunc        func(context.Context) (interface{}, error)
		algorithm      SignatureAlgorithm
		customClaims   func() CustomClaims
		expectedError  error
		expectedClaims *ValidatedClaims
	}{
		{
			name:  "it successfully validates a token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.ceqLpnraDGaKbQjIlyTFLj8WwwzGhBV3Eo9NDETEXTo",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   issuer,
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
		{
			name:  "it successfully validates a token with custom claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.Hu9l6uJppZs_-xoj_kQiLIUqaFV14vCLE3nSgx8VFRI",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return &testClaims{}
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   issuer,
					Subject:  subject,
					Audience: []string{audience},
				},
				CustomClaims: &testClaims{
					Scope: "read:messages",
				},
			},
		},
		{
			name:  "it throws an error when token has a different signing algorithm than the validator",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.ceqLpnraDGaKbQjIlyTFLj8WwwzGhBV3Eo9NDETEXTo",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     RS256,
			expectedError: errors.New(`could not parse the token: go-jose/go-jose: unexpected signature algorithm "HS256"; expected ["RS256"]`),
		},
		{
			name:  "it throws an error when it cannot parse the token",
			token: "",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("could not parse the token: go-jose/go-jose: compact JWS format must have three parts"),
		},
		{
			name:  "it throws an error when it fails to fetch the keys from the key func",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.ceqLpnraDGaKbQjIlyTFLj8WwwzGhBV3Eo9NDETEXTo",
			keyFunc: func(context.Context) (interface{}, error) {
				return nil, errors.New("key func error message")
			},
			algorithm:     HS256,
			expectedError: errors.New("failed to deserialize token claims: error getting the keys from the key func: key func error message"),
		},
		{
			name:  "it throws an error when it fails to deserialize the claims because the signature is invalid",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.vR2K2tZHDrgsEh9zNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("failed to deserialize token claims: could not get token claims: go-jose/go-jose: error in cryptographic primitive"),
		},
		{
			name:  "it throws an error when it fails to validate the registered claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIn0.U2heyMGWbMmhJvfYvXVPe1vK4TlNTiRKekU1EeTEN98",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("expected claims not validated: go-jose/go-jose/jwt: validation failed, invalid audience claim (aud)"),
		},
		{
			name:  "it throws an error when it fails to validate the custom claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.Hu9l6uJppZs_-xoj_kQiLIUqaFV14vCLE3nSgx8VFRI",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return &testClaims{
					ReturnError: errors.New("custom claims error message"),
				}
			},
			expectedError: errors.New("custom claims not validated: custom claims error message"),
		},
		{
			name:  "it successfully validates a token even if customClaims() returns nil",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.Hu9l6uJppZs_-xoj_kQiLIUqaFV14vCLE3nSgx8VFRI",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return nil
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   issuer,
					Subject:  subject,
					Audience: []string{audience},
				},
				CustomClaims: nil,
			},
		},
		{
			name:  "it successfully validates a token with exp, nbf and iat",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6MTY2NjkzOTAwMCwiZXhwIjo5NjY3OTM3Njg2fQ.F57edUPU8AEkIbLV8bLw1mw4RtKh6MtuPzoQQqin9kE",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:    issuer,
					Subject:   subject,
					Audience:  []string{audience},
					Expiry:    9667937686,
					NotBefore: 1666939000,
					IssuedAt:  1666937686,
				},
			},
		},
		{
			name:  "it throws an error when token is not valid yet",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6OTY2NjkzOTAwMCwiZXhwIjoxNjY3OTM3Njg2fQ.E8mqR42CRqEBcG9YzBVb8SGmitcU0sAMDbmG_ueM0EU",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("expected claims not validated: %s", jwt.ErrNotValidYet),
		},
		{
			name:  "it throws an error when token is expired",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6MTY2NjkzOTAwMCwiZXhwIjo2Njc5Mzc2ODZ9.iCJyAzGH5WXq8ffK8kEBumpilEqDHdB4V7X0nN4ppl0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("expected claims not validated: %s", jwt.ErrExpired),
		},
		{
			name:  "it throws an error when token is issued in the future",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjkxNjY2OTM3Njg2LCJuYmYiOjE2NjY5MzkwMDAsImV4cCI6ODY2NzkzNzY4Nn0.USKHRD2wUC5UuYLSL-nUJWs06emOxzX2M6Rv1OzxiM4",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("expected claims not validated: %s", jwt.ErrIssuedInTheFuture),
		},
		{
			name:  "it throws an error when token issuer is invalid",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2hhY2tlZC1qd3QtbWlkZGxld2FyZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6WyJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLWFwaS8iXSwiaWF0Ijo5MTY2NjkzNzY4NiwibmJmIjoxNjY2OTM5MDAwLCJleHAiOjg2Njc5Mzc2ODZ9.n-p1CVU0b5FwUIZr7nwl6CfpUq6GKmzBBaFVIGOT6w8",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("expected claims not validated: %s", jwt.ErrInvalidIssuer),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			validator, err := New(
				testCase.keyFunc,
				testCase.algorithm,
				issuer,
				[]string{audience, "another-audience"},
				WithCustomClaims(testCase.customClaims),
				WithAllowedClockSkew(time.Second),
			)
			require.NoError(t, err)

			tokenClaims, err := validator.ValidateToken(context.Background(), testCase.token)
			if testCase.expectedError != nil {
				assert.EqualError(t, err, testCase.expectedError.Error())
				assert.Nil(t, tokenClaims)
			} else {
				require.NoError(t, err)
				assert.Exactly(t, testCase.expectedClaims, tokenClaims)
			}
		})
	}
}

func TestNewValidator_ValidateToken(t *testing.T) {
	const (
		issuer    = "https://go-jwt-middleware.eu.auth0.com/"
		audience  = "https://go-jwt-middleware-api/"
		subject   = "1234567890"
		issuerB   = "https://go-jwt-middleware.us.auth0.com/"
		audienceB = "https://go-jwt-middleware-api-b/"
	)

	testCases := []struct {
		name           string
		token          string
		keyFunc        func(context.Context) (interface{}, error)
		algorithm      SignatureAlgorithm
		customClaims   func() CustomClaims
		expectedError  error
		expectedClaims *ValidatedClaims
	}{
		{
			name:  "it successfully validates a token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.ceqLpnraDGaKbQjIlyTFLj8WwwzGhBV3Eo9NDETEXTo",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   issuer,
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
		{
			name:  "it successfully validates a token with custom claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.Hu9l6uJppZs_-xoj_kQiLIUqaFV14vCLE3nSgx8VFRI",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return &testClaims{}
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   issuer,
					Subject:  subject,
					Audience: []string{audience},
				},
				CustomClaims: &testClaims{
					Scope: "read:messages",
				},
			},
		},
		{
			name:  "it throws an error when token has a different signing algorithm than the validator",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.ceqLpnraDGaKbQjIlyTFLj8WwwzGhBV3Eo9NDETEXTo",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     RS256,
			expectedError: errors.New(`could not parse the token: go-jose/go-jose: unexpected signature algorithm "HS256"; expected ["RS256"]`),
		},
		{
			name:  "it throws an error when it cannot parse the token",
			token: "",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("could not parse the token: go-jose/go-jose: compact JWS format must have three parts"),
		},
		{
			name:  "it throws an error when it fails to fetch the keys from the key func",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.ceqLpnraDGaKbQjIlyTFLj8WwwzGhBV3Eo9NDETEXTo",
			keyFunc: func(context.Context) (interface{}, error) {
				return nil, errors.New("key func error message")
			},
			algorithm:     HS256,
			expectedError: errors.New("failed to deserialize token claims: error getting the keys from the key func: key func error message"),
		},
		{
			name:  "it throws an error when it fails to deserialize the claims because the signature is invalid",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.vR2K2tZHDrgsEh9zNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("failed to deserialize token claims: could not get token claims: go-jose/go-jose: error in cryptographic primitive"),
		},
		{
			name:  "it throws an error when it fails to validate the registered claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIn0.U2heyMGWbMmhJvfYvXVPe1vK4TlNTiRKekU1EeTEN98",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("go-jose/go-jose/jwt: validation failed, invalid audience claim (aud)"),
		},
		{
			name:  "it throws an error when it fails to validate the custom claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.Hu9l6uJppZs_-xoj_kQiLIUqaFV14vCLE3nSgx8VFRI",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return &testClaims{
					ReturnError: errors.New("custom claims error message"),
				}
			},
			expectedError: errors.New("custom claims not validated: custom claims error message"),
		},
		{
			name:  "it successfully validates a token even if customClaims() returns nil",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.Hu9l6uJppZs_-xoj_kQiLIUqaFV14vCLE3nSgx8VFRI",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return nil
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   issuer,
					Subject:  subject,
					Audience: []string{audience},
				},
				CustomClaims: nil,
			},
		},
		{
			name:  "it successfully validates a token with exp, nbf and iat",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6MTY2NjkzOTAwMCwiZXhwIjo5NjY3OTM3Njg2fQ.F57edUPU8AEkIbLV8bLw1mw4RtKh6MtuPzoQQqin9kE",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm: HS256,
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:    issuer,
					Subject:   subject,
					Audience:  []string{audience},
					Expiry:    9667937686,
					NotBefore: 1666939000,
					IssuedAt:  1666937686,
				},
			},
		},
		{
			name:  "it throws an error when token is not valid yet",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6OTY2NjkzOTAwMCwiZXhwIjoxNjY3OTM3Njg2fQ.E8mqR42CRqEBcG9YzBVb8SGmitcU0sAMDbmG_ueM0EU",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("expected claims not validated: %s", jwt.ErrNotValidYet),
		},
		{
			name:  "it throws an error when token is expired",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6MTY2NjkzOTAwMCwiZXhwIjo2Njc5Mzc2ODZ9.iCJyAzGH5WXq8ffK8kEBumpilEqDHdB4V7X0nN4ppl0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("expected claims not validated: %s", jwt.ErrExpired),
		},
		{
			name:  "it throws an error when token is issued in the future",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjkxNjY2OTM3Njg2LCJuYmYiOjE2NjY5MzkwMDAsImV4cCI6ODY2NzkzNzY4Nn0.USKHRD2wUC5UuYLSL-nUJWs06emOxzX2M6Rv1OzxiM4",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("expected claims not validated: %s", jwt.ErrIssuedInTheFuture),
		},
		{
			name:  "it throws an error when token issuer is invalid",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2hhY2tlZC1qd3QtbWlkZGxld2FyZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6WyJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLWFwaS8iXSwiaWF0Ijo5MTY2NjkzNzY4NiwibmJmIjoxNjY2OTM5MDAwLCJleHAiOjg2Njc5Mzc2ODZ9.n-p1CVU0b5FwUIZr7nwl6CfpUq6GKmzBBaFVIGOT6w8",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("expected claims not validated: %s", jwt.ErrInvalidIssuer),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			validator, err := NewValidator(
				testCase.keyFunc,
				testCase.algorithm,
				WithCustomClaims(testCase.customClaims),
				WithAllowedClockSkew(time.Second),
				WithExpectedClaims(jwt.Expected{
					Issuer:      issuer,
					AnyAudience: []string{audience, "another-audience"},
				}, jwt.Expected{
					Issuer:      issuerB,
					AnyAudience: []string{audienceB, "another-audienceb"},
				}),
			)
			require.NoError(t, err)

			tokenClaims, err := validator.ValidateToken(context.Background(), testCase.token)
			if testCase.expectedError != nil {
				assert.ErrorContains(t, err, testCase.expectedError.Error())
				assert.Nil(t, tokenClaims)
			} else {
				require.NoError(t, err)
				assert.Exactly(t, testCase.expectedClaims, tokenClaims)
			}
		})
	}
}

func TestNew(t *testing.T) {
	const (
		issuer    = "https://go-jwt-middleware.eu.auth0.com/"
		audience  = "https://go-jwt-middleware-api/"
		algorithm = HS256
	)

	var keyFunc = func(context.Context) (interface{}, error) {
		return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
	}

	t.Run("it throws an error when the keyFunc is nil", func(t *testing.T) {
		_, err := New(nil, algorithm, issuer, []string{audience})
		assert.EqualError(t, err, "keyFunc is required but was nil")
	})

	t.Run("it throws an error when the signature algorithm is empty", func(t *testing.T) {
		_, err := New(keyFunc, "", issuer, []string{audience})
		assert.EqualError(t, err, "unsupported signature algorithm")
	})

	t.Run("it throws an error when the signature algorithm is unsupported", func(t *testing.T) {
		_, err := New(keyFunc, "none", issuer, []string{audience})
		assert.EqualError(t, err, "unsupported signature algorithm")
	})

	t.Run("it throws an error when the issuerURL is empty and no expectedClaims option", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, "", []string{audience})
		assert.EqualError(t, err, "issuer url is required but was empty")
	})

	t.Run("it throws an error when the audience is nil if no expectedClaims option included", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, issuer, nil)
		assert.EqualError(t, err, "audience is required but was empty")
	})

	t.Run("it throws an error when the audience is empty", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, issuer, []string{})
		assert.EqualError(t, err, "audience is required but was empty")
	})

	t.Run("it throws an error when the issuerURL is empty and an expectedClaims option with only an audience", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, "", []string{}, WithExpectedClaims(jwt.Expected{AnyAudience: []string{audience}}))
		assert.EqualError(t, err, "issuer url 0 is required but was empty")
	})

	t.Run("it throws an error when the audience is empty and the expectedClaims are missing an audience", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, issuer, []string{}, WithExpectedClaims(jwt.Expected{Issuer: issuer}))
		assert.EqualError(t, err, "audience 0 is required but was empty")
	})

	t.Run("it throws no error when the issuerURL is empty but expectedClaims option included", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, "", []string{audience}, WithExpectedClaims(jwt.Expected{Issuer: issuer, AnyAudience: []string{audience}}))
		assert.NoError(t, err, "no error was expected")
	})

	t.Run("it throws no error when the audience is nil but expectedClaims option included", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, issuer, nil, WithExpectedClaims(jwt.Expected{Issuer: issuer, AnyAudience: []string{audience}}))
		assert.NoError(t, err, "no error was expected")
	})
}

func TestNewValidator(t *testing.T) {
	const (
		issuer    = "https://go-jwt-middleware.eu.auth0.com/"
		audience  = "https://go-jwt-middleware-api/"
		algorithm = HS256
	)

	var keyFunc = func(context.Context) (interface{}, error) {
		return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil
	}

	t.Run("it throws an error when the keyFunc is nil", func(t *testing.T) {
		_, err := NewValidator(nil, algorithm)
		assert.EqualError(t, err, "keyFunc is required but was nil")
	})

	t.Run("it throws an error when the signature algorithm is empty", func(t *testing.T) {
		_, err := NewValidator(keyFunc, "")
		assert.EqualError(t, err, "unsupported signature algorithm")
	})

	t.Run("it throws an error when the signature algorithm is unsupported", func(t *testing.T) {
		_, err := NewValidator(keyFunc, "none")
		assert.EqualError(t, err, "unsupported signature algorithm")
	})

	t.Run("it throws an error when there are no expected claims", func(t *testing.T) {
		_, err := NewValidator(keyFunc, algorithm)
		assert.EqualError(t, err, "expected claims but none provided")
	})

	t.Run("it throws an error when expectedClaims option with only an audience", func(t *testing.T) {
		_, err := NewValidator(keyFunc, algorithm, WithExpectedClaims(jwt.Expected{AnyAudience: []string{audience}}))
		assert.EqualError(t, err, "issuer url 0 is required but was empty")
	})

	t.Run("it throws an error when expectedClaims option with only an audience in the second jwt.Expected", func(t *testing.T) {
		_, err := NewValidator(keyFunc, algorithm, WithExpectedClaims(jwt.Expected{Issuer: issuer, AnyAudience: []string{audience}}, jwt.Expected{AnyAudience: []string{audience}}))
		assert.EqualError(t, err, "issuer url 1 is required but was empty")
	})

	t.Run("it throws an error when the audience is empty and the expectedClaims are missing an audience", func(t *testing.T) {
		_, err := NewValidator(keyFunc, algorithm, WithExpectedClaims(jwt.Expected{Issuer: issuer}))
		assert.EqualError(t, err, "audience 0 is required but was empty")
	})

	t.Run("it throws an error when the audience is empty and the expectedClaims are missing an audience in the second jwt.Expected", func(t *testing.T) {
		_, err := NewValidator(keyFunc, algorithm, WithExpectedClaims(jwt.Expected{Issuer: issuer, AnyAudience: []string{audience}}, jwt.Expected{Issuer: issuer}))
		assert.EqualError(t, err, "audience 1 is required but was empty")
	})

	t.Run("it throws no error when input is correct", func(t *testing.T) {
		_, err := NewValidator(keyFunc, algorithm, WithExpectedClaims(jwt.Expected{Issuer: issuer, AnyAudience: []string{audience}}))
		assert.NoError(t, err, "no error was expected")
	})
}
