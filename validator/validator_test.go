package validator

import (
	"context"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
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
		options        []Option
		expectedError  error
		expectedClaims *ValidatedClaims
	}{
		{
			name:  "it successfully validates a token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
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
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.oqtUZQ-Q8un4CPduUBdGVq5gXpQVIFT_QSQjkOXFT5I",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return &testClaims{}
			},
			options: []Option{
				WithCustomClaims(func() CustomClaims {
					return &testClaims{
						Scope: "read:messages",
					}
				}),
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
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     RS256,
			expectedError: errors.New(`token validation failed: could not verify message using any of the signatures or keys`),
		},
		{
			name:  "it throws an error when it cannot parse the token",
			token: "",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("token is malformed"),
		},
		{
			name:  "it throws an error when it fails to fetch the keys from the key func",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return nil, errors.New("key func error message")
			},
			algorithm:     HS256,
			expectedError: errors.New("failed to get key: key func error message"),
		},
		{
			name:  "it throws an error when it fails to deserialize the claims because the signature is invalid",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.vR2K2tZHDrgsEh9zNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("token validation failed: could not verify message using any of the signatures or keys"),
		},
		{
			name:  "it throws an error when it fails to validate the registered claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIn0.VoIwDVmb--26wGrv93NmjNZYa4nrzjLw4JANgEjPI28",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("token validation failed: missing audience claim"),
		},
		{
			name:  "it throws an error when it fails to validate the custom claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.oqtUZQ-Q8un4CPduUBdGVq5gXpQVIFT_QSQjkOXFT5I",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return &testClaims{
					ReturnError: errors.New("custom claims error message"),
				}
			},
			options: []Option{
				WithCustomClaims(func() CustomClaims {
					return &testClaims{
						ReturnError: errors.New("custom claims error message"),
					}
				}),
			},
			expectedError: errors.New("custom claims validation failed: custom claims error message"),
		},
		{
			name:  "it successfully validates a token even if customClaims() returns nil",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJzY29wZSI6InJlYWQ6bWVzc2FnZXMifQ.oqtUZQ-Q8un4CPduUBdGVq5gXpQVIFT_QSQjkOXFT5I",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm: HS256,
			customClaims: func() CustomClaims {
				return nil
			},
			options: []Option{
				WithCustomClaims(func() CustomClaims {
					return nil
				}),
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
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6MTY2NjkzOTAwMCwiZXhwIjo5NjY3OTM3Njg2fQ.FKZogkm08gTfYfPU6eYu7OHCjJKnKGLiC0IfoIOPEhs",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
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
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6OTY2NjkzOTAwMCwiZXhwIjoxNjY3OTM3Njg2fQ.yUizJ-zK_33tv1qBVvDKO0RuCWtvJ02UQKs8gBadgGY",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("token validation failed: \"exp\" not satisfied"),
		},
		{
			name:  "it throws an error when token is expired",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6MTY2NjkzOTAwMCwiZXhwIjo2Njc5Mzc2ODZ9.SKvz82VOXRi_sjvZWIsPG9vSWAXKKgVS4DkGZcwFKL8",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("token validation failed: \"exp\" not satisfied"),
		},
		{
			name:  "it throws an error when token is issued in the future",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjkxNjY2OTM3Njg2LCJuYmYiOjE2NjY5MzkwMDAsImV4cCI6ODY2NzkzNzY4Nn0.ieFV7XNJxiJyw8ARq9yHw-01Oi02e3P2skZO10ypxL8",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("token validation failed: \"iat\" not satisfied"),
		},
		{
			name:  "it throws an error when token issuer is invalid",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2hhY2tlZC1qd3QtbWlkZGxld2FyZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6WyJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLWFwaS8iXSwiaWF0Ijo5MTY2NjkzNzY4NiwibmJmIjoxNjY2OTM5MDAwLCJleHAiOjg2Njc5Mzc2ODZ9.b5gXNrUNfd_jyCWZF-6IPK_UFfvTr9wBQk9_QgRQ8rA",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: fmt.Errorf("token validation failed: \"iat\" not satisfied"),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			validator, err := New(
				testCase.keyFunc,
				testCase.algorithm,
				[]string{issuer},
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

func TestNewValidator(t *testing.T) {
	const (
		issuer    = "https://go-jwt-middleware.eu.auth0.com/"
		audience  = "https://go-jwt-middleware-api/"
		algorithm = HS256
	)

	var keyFunc = func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}

	t.Run("it throws an error when the keyFunc is nil", func(t *testing.T) {
		_, err := New(nil, algorithm, []string{issuer}, []string{audience})
		assert.EqualError(t, err, ErrKeyFuncRequired.Error())
	})

	t.Run("it throws an error when the signature algorithm is empty", func(t *testing.T) {
		_, err := New(keyFunc, "", []string{issuer}, []string{audience})
		assert.EqualError(t, err, ErrUnsupportedAlgorithm.Error())
	})

	t.Run("it throws an error when the signature algorithm is unsupported", func(t *testing.T) {
		_, err := New(keyFunc, "none", []string{issuer}, []string{audience})
		assert.EqualError(t, err, ErrUnsupportedAlgorithm.Error())
	})

	t.Run("it throws an error when the issuerURL is empty", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, []string{}, []string{audience})
		assert.EqualError(t, err, ErrIssuerURLRequired.Error())
	})

	t.Run("it throws an error when the audience is nil", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, []string{issuer}, nil)
		assert.EqualError(t, err, ErrAudienceRequired.Error())
	})

	t.Run("it throws an error when the audience is empty", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, []string{issuer}, []string{})
		assert.EqualError(t, err, ErrAudienceRequired.Error())
	})

	t.Run("it throws an error when a functional option returns an error", func(t *testing.T) {
		_, err := New(keyFunc, algorithm, []string{issuer}, []string{audience}, func(*Validator) error {
			return errors.New("functional option error")
		})
		assert.EqualError(t, err, "functional option error")
	})
}

func createTestToken(t *testing.T, issuer, audience, subject string, keyFunc func(context.Context) (interface{}, error)) string {
	claims := jwt.New()
	err := claims.Set(jwt.IssuerKey, issuer)
	if err != nil {
		return fmt.Errorf("failed to set issuer claim: %w", err).Error()
	}
	err = claims.Set(jwt.SubjectKey, subject)
	if err != nil {
		return fmt.Errorf("failed to set subject claim: %w", err).Error()
	}
	err = claims.Set(jwt.AudienceKey, audience)
	if err != nil {
		return fmt.Errorf("failed to set audience claim: %w", err).Error()
	}

	key, err := keyFunc(context.Background())
	require.NoError(t, err)

	token, err := jwt.Sign(claims, jwt.WithKey(jwa.SignatureAlgorithm(HS256), key))
	require.NoError(t, err)

	return string(token)
}

func TestValidator_ValidateToken_MultipleIssuers(t *testing.T) {
	const (
		primaryIssuer   = "https://primary.auth0.com/"
		secondaryIssuer = "https://secondary.auth0.com/"
		audience        = "https://go-jwt-middleware-api/"
		subject         = "1234567890"
	)

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}
	primaryToken := createTestToken(t, primaryIssuer, audience, subject, keyFunc)
	secondaryToken := createTestToken(t, secondaryIssuer, audience, subject, keyFunc)
	unknownIssuerToken := createTestToken(t, "https://unknown.auth0.com/", audience, subject, keyFunc)

	testCases := []struct {
		name           string
		token          string
		issuers        []string
		options        []Option
		expectedError  error
		expectedClaims *ValidatedClaims
	}{
		{
			name:    "accepts token with the primary issuer",
			token:   primaryToken,
			issuers: []string{primaryIssuer, secondaryIssuer},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   primaryIssuer,
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
		{
			name:    "accepts token with the secondary issuer",
			token:   secondaryToken,
			issuers: []string{primaryIssuer, secondaryIssuer},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   secondaryIssuer,
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
		{
			name:          "rejects token with unknown issuer",
			token:         unknownIssuerToken,
			issuers:       []string{primaryIssuer, secondaryIssuer},
			expectedError: fmt.Errorf(`token issuer "https://unknown.auth0.com/" not in allowed issuers list`),
		},
		{
			name:    "accepts token with issuer added via WithAdditionalIssuers",
			token:   unknownIssuerToken,
			issuers: []string{primaryIssuer, secondaryIssuer},
			options: []Option{
				WithAdditionalIssuers([]string{"https://unknown.auth0.com/"}),
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   "https://unknown.auth0.com/",
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
		{
			name:    "overrides issuers with WithExpectedIssuers",
			token:   unknownIssuerToken,
			issuers: []string{primaryIssuer, secondaryIssuer},
			options: []Option{
				WithExpectedIssuers([]string{"https://unknown.auth0.com/"}),
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   "https://unknown.auth0.com/",
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			validator, err := New(
				keyFunc,
				HS256,
				testCase.issuers,
				[]string{audience},
				WithAllowedClockSkew(time.Second),
			)
			require.NoError(t, err)

			// Apply additional options if provided
			for _, opt := range testCase.options {
				err := opt(validator)
				require.NoError(t, err)
			}

			tokenClaims, err := validator.ValidateToken(context.Background(), testCase.token)
			if testCase.expectedError != nil {
				assert.EqualError(t, err, testCase.expectedError.Error())
				assert.Nil(t, tokenClaims)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Issuer, tokenClaims.(*ValidatedClaims).RegisteredClaims.Issuer)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Subject, tokenClaims.(*ValidatedClaims).RegisteredClaims.Subject)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Audience, tokenClaims.(*ValidatedClaims).RegisteredClaims.Audience)
			}
		})
	}
}

func TestValidator_SkipIssuerValidation(t *testing.T) {
	const (
		primaryIssuer = "https://primary.auth0.com/"
		audience      = "https://go-jwt-middleware-api/"
		subject       = "1234567890"
	)

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}

	// Token with an unknown issuer
	unknownIssuerToken := createTestToken(t, "https://unknown.auth0.com/", audience, subject, keyFunc)

	testCases := []struct {
		name           string
		token          string
		issuers        []string
		skipValidation bool
		expectedError  error
		expectedClaims *ValidatedClaims
	}{
		{
			name:           "rejects token with unknown issuer when not skipping validation",
			token:          unknownIssuerToken,
			issuers:        []string{primaryIssuer},
			skipValidation: false,
			expectedError:  fmt.Errorf(`token issuer "https://unknown.auth0.com/" not in allowed issuers list`),
		},
		{
			name:           "accepts token with unknown issuer when skipping validation",
			token:          unknownIssuerToken,
			issuers:        []string{primaryIssuer},
			skipValidation: true,
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   "https://unknown.auth0.com/",
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
		{
			name:           "allows empty issuers list when skipping validation",
			token:          unknownIssuerToken,
			issuers:        []string{},
			skipValidation: true,
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   "https://unknown.auth0.com/",
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var validator *Validator
			var err error

			if testCase.skipValidation {
				validator, err = New(
					keyFunc,
					HS256,
					testCase.issuers,
					[]string{audience},
					WithSkipIssuerValidation(),
				)
			} else {
				validator, err = New(
					keyFunc,
					HS256,
					testCase.issuers,
					[]string{audience},
				)
			}

			if len(testCase.issuers) == 0 && !testCase.skipValidation {
				assert.Equal(t, ErrIssuerURLRequired, err)
				return
			}

			require.NoError(t, err)

			tokenClaims, err := validator.ValidateToken(context.Background(), testCase.token)
			if testCase.expectedError != nil {
				assert.EqualError(t, err, testCase.expectedError.Error())
				assert.Nil(t, tokenClaims)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Issuer, tokenClaims.(*ValidatedClaims).RegisteredClaims.Issuer)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Subject, tokenClaims.(*ValidatedClaims).RegisteredClaims.Subject)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Audience, tokenClaims.(*ValidatedClaims).RegisteredClaims.Audience)
			}
		})
	}
}

func TestNew_WithSkipIssuerValidation(t *testing.T) {
	const (
		audience = "https://go-jwt-middleware-api/"
	)

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}

	t.Run("it allows empty issuerURLs when WithSkipIssuerValidation is provided", func(t *testing.T) {
		validator, err := New(
			keyFunc,
			HS256,
			[]string{},
			[]string{audience},
			WithSkipIssuerValidation(),
		)

		assert.NoError(t, err)
		assert.NotNil(t, validator)
		assert.True(t, validator.skipIssuerValidation)
	})

	t.Run("it requires issuerURLs when WithSkipIssuerValidation is not provided", func(t *testing.T) {
		_, err := New(
			keyFunc,
			HS256,
			[]string{},
			[]string{audience},
		)

		assert.Equal(t, ErrIssuerURLRequired, err)
	})
}

func TestValidator_OptionCombinations(t *testing.T) {
	const (
		primaryIssuer   = "https://primary.auth0.com/"
		secondaryIssuer = "https://secondary.auth0.com/"
		audience        = "https://go-jwt-middleware-api/"
		subject         = "1234567890"
	)

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}
	unknownIssuerToken := createTestToken(t, "https://unknown.auth0.com/", audience, subject, keyFunc)

	testCases := []struct {
		name           string
		token          string
		options        []Option
		expectedError  error
		expectedClaims *ValidatedClaims
	}{
		{
			name:  "combining WithSkipIssuerValidation and WithExpectedIssuers skips validation",
			token: unknownIssuerToken,
			options: []Option{
				WithSkipIssuerValidation(),
				WithExpectedIssuers([]string{primaryIssuer}),
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   "https://unknown.auth0.com/",
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
		{
			name:  "WithSkipIssuerValidation takes precedence over WithExpectedIssuers",
			token: unknownIssuerToken,
			options: []Option{
				WithExpectedIssuers([]string{primaryIssuer}),
				WithSkipIssuerValidation(),
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   "https://unknown.auth0.com/",
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
		{
			name:  "WithAdditionalIssuers and WithExpectedIssuers work together",
			token: unknownIssuerToken,
			options: []Option{
				WithExpectedIssuers([]string{primaryIssuer}),
				WithAdditionalIssuers([]string{"https://unknown.auth0.com/"}),
			},
			expectedClaims: &ValidatedClaims{
				RegisteredClaims: RegisteredClaims{
					Issuer:   "https://unknown.auth0.com/",
					Subject:  subject,
					Audience: []string{audience},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			validator, err := New(
				keyFunc,
				HS256,
				[]string{primaryIssuer, secondaryIssuer},
				[]string{audience},
			)
			require.NoError(t, err)

			// Apply all options
			for _, opt := range testCase.options {
				err := opt(validator)
				require.NoError(t, err)
			}

			tokenClaims, err := validator.ValidateToken(context.Background(), testCase.token)
			if testCase.expectedError != nil {
				assert.EqualError(t, err, testCase.expectedError.Error())
				assert.Nil(t, tokenClaims)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Issuer, tokenClaims.(*ValidatedClaims).RegisteredClaims.Issuer)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Subject, tokenClaims.(*ValidatedClaims).RegisteredClaims.Subject)
				assert.Equal(t, testCase.expectedClaims.RegisteredClaims.Audience, tokenClaims.(*ValidatedClaims).RegisteredClaims.Audience)
			}
		})
	}
}

// Add these additional test functions to the existing validator_test.go file

// Test case for invalid audience claim
func TestValidator_InvalidAudienceClaim(t *testing.T) {
	// Create a token with wrong audience values
	token := jwt.New()
	err := token.Set(jwt.IssuerKey, "https://issuer.example.com/")
	require.NoError(t, err)
	err = token.Set(jwt.AudienceKey, []string{"wrong-audience1", "wrong-audience2"})
	require.NoError(t, err)

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte("secret")))
	require.NoError(t, err)

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}

	// Create validator with different expected audiences
	validator, err := New(
		keyFunc,
		HS256,
		[]string{"https://issuer.example.com/"},
		[]string{"expected-audience1", "expected-audience2"},
	)
	require.NoError(t, err)

	// This should fail because the token audiences don't match any of the expected audiences
	result, err := validator.ValidateToken(context.Background(), string(signedToken))

	// Assertions
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid audience claim")
}

// Test custom claims with errors at different stages of processing
func TestValidator_CustomClaimsProcessingErrors(t *testing.T) {
	// Set up a basic token with required fields
	ctx := context.Background()

	// Test custom claims unmarshaling error
	t.Run("unmarshal error", func(t *testing.T) {
		// Create a token with a field that will cause an unmarshal error
		token := jwt.New()
		err := token.Set(jwt.IssuerKey, "https://issuer.example.com/")
		require.NoError(t, err)
		err = token.Set(jwt.AudienceKey, []string{"https://audience.example.com/"})
		require.NoError(t, err)
		err = token.Set("scope", 12345) // This is an integer, but the custom claims expects a string
		require.NoError(t, err)

		signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte("secret")))
		require.NoError(t, err)

		keyFunc := func(context.Context) (interface{}, error) {
			return []byte("secret"), nil
		}

		validator, err := New(
			keyFunc,
			HS256,
			[]string{"https://issuer.example.com/"},
			[]string{"https://audience.example.com/"},
			WithCustomClaims(func() CustomClaims {
				return &testClaims{} // Expects "scope" to be a string
			}),
		)
		require.NoError(t, err)

		// Should fail during custom claims unmarshaling
		result, err := validator.ValidateToken(ctx, string(signedToken))
		assert.Nil(t, result)
		assert.Equal(t, ErrClaimsMappingFailed, err)
	})

	// Test custom claims validation error
	t.Run("validation error", func(t *testing.T) {
		token := jwt.New()
		err := token.Set(jwt.IssuerKey, "https://issuer.example.com/")
		require.NoError(t, err)
		err = token.Set(jwt.AudienceKey, []string{"https://audience.example.com/"})
		require.NoError(t, err)
		err = token.Set("scope", "read:data")
		require.NoError(t, err)

		signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte("secret")))
		require.NoError(t, err)

		customErr := errors.New("custom validation error")

		validator, err := New(
			func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			HS256,
			[]string{"https://issuer.example.com/"},
			[]string{"https://audience.example.com/"},
			WithCustomClaims(func() CustomClaims {
				return &testClaims{
					ReturnError: customErr,
				}
			}),
		)
		require.NoError(t, err)

		// Should fail during custom claims validation
		result, err := validator.ValidateToken(ctx, string(signedToken))
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "custom claims validation failed")
		assert.Contains(t, err.Error(), customErr.Error())
	})
}

// Test missing audience claim
func TestValidator_MissingAudienceClaim(t *testing.T) {
	// Create a token without an audience claim
	token := jwt.New()
	err := token.Set(jwt.IssuerKey, "https://issuer.example.com/")
	require.NoError(t, err)
	// Deliberately skip setting audience

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte("secret")))
	require.NoError(t, err)

	validator, err := New(
		func(context.Context) (interface{}, error) {
			return []byte("secret"), nil
		},
		HS256,
		[]string{"https://issuer.example.com/"},
		[]string{"expected-audience"},
	)
	require.NoError(t, err)

	// Should fail due to missing audience
	result, err := validator.ValidateToken(context.Background(), string(signedToken))
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing audience claim")
}

// Test with multiple expected audiences
func TestValidator_MultipleExpectedAudiences(t *testing.T) {
	// Create a token with a single audience
	token := jwt.New()
	err := token.Set(jwt.IssuerKey, "https://issuer.example.com/")
	require.NoError(t, err)
	err = token.Set(jwt.AudienceKey, []string{"audience2"})
	require.NoError(t, err)

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte("secret")))
	require.NoError(t, err)

	// Create validator with multiple expected audiences
	validator, err := New(
		func(context.Context) (interface{}, error) {
			return []byte("secret"), nil
		},
		HS256,
		[]string{"https://issuer.example.com/"},
		[]string{"audience1", "audience2", "audience3"}, // audience2 should match
	)
	require.NoError(t, err)

	// Should succeed because one audience matches
	result, err := validator.ValidateToken(context.Background(), string(signedToken))
	assert.NoError(t, err)
	assert.NotNil(t, result)

	validatedClaims, ok := result.(*ValidatedClaims)
	require.True(t, ok)
	assert.Equal(t, "https://issuer.example.com/", validatedClaims.RegisteredClaims.Issuer)
	assert.Contains(t, validatedClaims.RegisteredClaims.Audience, "audience2")
}

// Test customClaimsExist function
func TestCustomClaimsExist(t *testing.T) {
	t.Run("nil custom claims function", func(t *testing.T) {
		validator := &Validator{
			customClaims: nil,
		}
		assert.False(t, validator.customClaimsExist())
	})

	t.Run("custom claims function returns nil", func(t *testing.T) {
		validator := &Validator{
			customClaims: func() CustomClaims {
				return nil
			},
		}
		assert.False(t, validator.customClaimsExist())
	})

	t.Run("custom claims function returns non-nil", func(t *testing.T) {
		validator := &Validator{
			customClaims: func() CustomClaims {
				return &testClaims{}
			},
		}
		assert.True(t, validator.customClaimsExist())
	})
}
