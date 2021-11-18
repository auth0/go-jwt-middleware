package josev2

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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
		name            string
		token           string
		keyFunc         func(context.Context) (interface{}, error)
		algorithm       jose.SignatureAlgorithm
		customClaims    CustomClaims
		expectedError   error
		expectedContext *UserContext
	}{
		{
			name:  "it successfully validates a token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			expectedContext: &UserContext{
				RegisteredClaims: jwt.Claims{
					Issuer:   issuer,
					Subject:  subject,
					Audience: jwt.Audience{audience},
				},
			},
		},
		{
			name:  "it successfully validates a token with custom claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.oqtUZQ-Q8un4CPduUBdGVq5gXpQVIFT_QSQjkOXFT5I",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			customClaims: &testClaims{},
			expectedContext: &UserContext{
				RegisteredClaims: jwt.Claims{
					Issuer:   issuer,
					Subject:  subject,
					Audience: jwt.Audience{audience},
				},
				CustomClaims: &testClaims{
					Scope: "read:messages",
				},
			},
		},
		{
			name:  "it throws an error when token has a different signing algorithm than the validator",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     jose.RS256,
			expectedError: errors.New(`expected "RS256" signing algorithm but token specified "HS256"`),
		},
		{
			name:  "it throws an error when it cannot parse the token",
			token: "",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			expectedError: errors.New("could not parse the token: square/go-jose: compact JWS format must have three parts"),
		},
		{
			name:  "it throws an error when it fails to fetch the keys from the key func",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return nil, errors.New("key func error message")
			},
			expectedError: errors.New("error getting the keys from the key func: key func error message"),
		},
		{
			name:  "it throws an error when it fails to deserialize the claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.vR2K2tZHDrgsEh9zNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			expectedError: errors.New("could not get token claims: square/go-jose: error in cryptographic primitive"),
		},
		{
			name:  "it throws an error when it fails to validate the registered claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIn0.VoIwDVmb--26wGrv93NmjNZYa4nrzjLw4JANgEjPI28",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			expectedError: errors.New("expected claims not validated: square/go-jose/jwt: validation failed, invalid audience claim (aud)"),
		},
		{
			name:  "it throws an error when it fails to validate the custom claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.oqtUZQ-Q8un4CPduUBdGVq5gXpQVIFT_QSQjkOXFT5I",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			customClaims: &testClaims{
				ReturnError: errors.New("custom claims error message"),
			},
			expectedError: errors.New("custom claims not validated: custom claims error message"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.algorithm == "" {
				testCase.algorithm = jose.HS256
			}

			validator, err := New(
				testCase.keyFunc,
				testCase.algorithm,
				issuer,
				jwt.Audience{audience},
				WithCustomClaims(testCase.customClaims),
			)
			if err != nil {
				t.Fatalf("expected not to err but got: %v", err)
			}

			actualContext, err := validator.ValidateToken(context.Background(), testCase.token)
			if testCase.expectedError != nil {
				if testCase.expectedError.Error() != err.Error() {
					t.Fatalf("wanted err: %v, but got: %v", testCase.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected not to err but got: %v", err)
				}

				if !cmp.Equal(testCase.expectedContext, actualContext.(*UserContext)) {
					t.Fatalf(
						"user context did not match: %s",
						cmp.Diff(testCase.expectedContext, actualContext.(*UserContext)),
					)
				}
			}
		})
	}
}
