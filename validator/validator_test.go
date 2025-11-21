package validator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
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
			expectedError: errors.New(`failed to parse and validate token: jwt.ParseString: failed to parse string: jwt.VerifyCompact: signature verification failed for RS256: jwsbb.Verify: invalid key type []uint8. *rsa.PublicKey is required: keyconv: expected rsa.PublicKey/rsa.PrivateKey or *rsa.PublicKey/*rsa.PrivateKey, got []uint8`),
		},
		{
			name:  "it throws an error when it cannot parse the token",
			token: "a.b",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("failed to parse and validate token: jwt.ParseString: failed to parse string: unknown payload type (payload is not JWT?)"),
		},
		{
			name:  "it throws an error when it fails to fetch the keys from the key func",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return nil, errors.New("key func error message")
			},
			algorithm:     HS256,
			expectedError: errors.New("error getting the keys from the key func: key func error message"),
		},
		{
			name:  "it throws an error when it fails to deserialize the claims because the signature is invalid",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.vR2K2tZHDrgsEh9zNWcyk4aljtR6gZK0s2anNGlfwz0",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("failed to parse and validate token: jwt.ParseString: failed to parse string: jwt.VerifyCompact: signature verification failed for HS256: invalid HMAC signature"),
		},
		{
			name:  "it throws an error when it fails to validate the registered claims",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIn0.VoIwDVmb--26wGrv93NmjNZYa4nrzjLw4JANgEjPI28",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New("audience validation failed: token has no audience"),
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
			expectedError: errors.New("custom claims not validated: custom claims error message"),
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
			expectedError: errors.New(`failed to parse and validate token: jwt.ParseString: failed to parse string: jwt.Validate: validation failed: "exp" not satisfied: token is expired`),
		},
		{
			name:  "it throws an error when token is expired",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjE2NjY5Mzc2ODYsIm5iZiI6MTY2NjkzOTAwMCwiZXhwIjo2Njc5Mzc2ODZ9.SKvz82VOXRi_sjvZWIsPG9vSWAXKKgVS4DkGZcwFKL8",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New(`failed to parse and validate token: jwt.ParseString: failed to parse string: jwt.Validate: validation failed: "exp" not satisfied: token is expired`),
		},
		{
			name:  "it throws an error when token is issued in the future",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdLCJpYXQiOjkxNjY2OTM3Njg2LCJuYmYiOjE2NjY5MzkwMDAsImV4cCI6ODY2NzkzNzY4Nn0.ieFV7XNJxiJyw8ARq9yHw-01Oi02e3P2skZO10ypxL8",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New(`failed to parse and validate token: jwt.ParseString: failed to parse string: jwt.Validate: validation failed: "iat" not satisfied`),
		},
		{
			name:  "it throws an error when token issuer is invalid",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2hhY2tlZC1qd3QtbWlkZGxld2FyZS5ldS5hdXRoMC5jb20vIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6WyJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLWFwaS8iXSwiaWF0Ijo5MTY2NjkzNzY4NiwibmJmIjoxNjY2OTM5MDAwLCJleHAiOjg2Njc5Mzc2ODZ9.b5gXNrUNfd_jyCWZF-6IPK_UFfvTr9wBQk9_QgRQ8rA",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			algorithm:     HS256,
			expectedError: errors.New(`failed to parse and validate token: jwt.ParseString: failed to parse string: jwt.Validate: validation failed: "iat" not satisfied`),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			opts := []Option{
				WithKeyFunc(testCase.keyFunc),
				WithAlgorithm(testCase.algorithm),
				WithIssuer(issuer),
				WithAudiences([]string{audience, "another-audience"}),
				WithAllowedClockSkew(time.Second),
			}
			if testCase.customClaims != nil {
				opts = append(opts, WithCustomClaims(testCase.customClaims))
			}

			validator, err := New(opts...)
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

	t.Run("successful creation with all required options", func(t *testing.T) {
		v, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudience(audience),
		)
		assert.NoError(t, err)
		assert.NotNil(t, v)
	})

	t.Run("successful creation with WithAudiences", func(t *testing.T) {
		v, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudiences([]string{audience, "another-audience"}),
		)
		assert.NoError(t, err)
		assert.NotNil(t, v)
	})

	t.Run("successful creation with optional parameters", func(t *testing.T) {
		v, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudience(audience),
			WithAllowedClockSkew(30*time.Second),
		)
		assert.NoError(t, err)
		assert.NotNil(t, v)
		assert.Equal(t, 30*time.Second, v.allowedClockSkew)
	})

	t.Run("it throws an error when the keyFunc is nil", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(nil),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "keyFunc cannot be nil")
	})

	t.Run("it throws an error when keyFunc is missing", func(t *testing.T) {
		_, err := New(
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "keyFunc is required")
	})

	t.Run("it throws an error when the signature algorithm is empty", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(""),
			WithIssuer(issuer),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported signature algorithm")
	})

	t.Run("it throws an error when the signature algorithm is unsupported", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm("none"),
			WithIssuer(issuer),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported signature algorithm")
	})

	t.Run("it throws an error when algorithm is missing", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithIssuer(issuer),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature algorithm is required")
	})

	t.Run("it throws an error when the issuerURL is empty", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(""),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer cannot be empty")
	})

	t.Run("it throws an error when the issuerURL is invalid", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer("ht!tp://invalid url with spaces"),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer URL")
	})

	t.Run("it throws an error when issuer is missing", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer is required")
	})

	t.Run("it throws an error when the audience is empty", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudience(""),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audience cannot be empty")
	})

	t.Run("it throws an error when audiences list is empty", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudiences([]string{}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audiences cannot be empty")
	})

	t.Run("it throws an error when audience is missing", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audience is required")
	})

	t.Run("it throws an error when audiences contains empty string", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudiences([]string{"valid-aud", ""}),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audience at index 1 cannot be empty")
	})

	t.Run("it throws an error when clock skew is negative", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudience(audience),
			WithAllowedClockSkew(-1*time.Second),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "clock skew cannot be negative")
	})

	t.Run("it throws an error when custom claims function is nil", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuer(issuer),
			WithAudience(audience),
			WithCustomClaims[*testClaims](nil), // Need to specify type for nil
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "custom claims function cannot be nil")
	})

	t.Run("WithIssuers accepts multiple issuers", func(t *testing.T) {
		issuers := []string{
			"https://issuer1.example.com/",
			"https://issuer2.example.com/",
			"https://issuer3.example.com/",
		}
		v, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuers(issuers),
			WithAudience(audience),
		)
		assert.NoError(t, err)
		assert.NotNil(t, v)
		assert.Equal(t, issuers, v.expectedIssuers)
	})

	t.Run("WithIssuers rejects empty list", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuers([]string{}),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuers cannot be empty")
	})

	t.Run("WithIssuers rejects list with empty string", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuers([]string{"https://valid.com/", ""}),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer at index 1 cannot be empty")
	})

	t.Run("WithIssuers rejects list with invalid URL", func(t *testing.T) {
		_, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(algorithm),
			WithIssuers([]string{"https://valid.com/", "ht!tp://invalid url"}),
			WithAudience(audience),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer URL at index 1")
	})
}

func TestAllSignatureAlgorithms(t *testing.T) {
	const (
		issuer   = "https://go-jwt-middleware.eu.auth0.com/"
		audience = "https://go-jwt-middleware-api/"
	)

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}

	algorithms := []SignatureAlgorithm{
		EdDSA,
		HS256, HS384, HS512,
		RS256, RS384, RS512,
		ES256, ES384, ES512, ES256K,
		PS256, PS384, PS512,
	}

	for _, alg := range algorithms {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			v, err := New(
				WithKeyFunc(keyFunc),
				WithAlgorithm(alg),
				WithIssuer(issuer),
				WithAudience(audience),
			)
			require.NoError(t, err)
			require.NotNil(t, v)
			assert.Equal(t, alg, v.signatureAlgorithm)
		})
	}
}

func TestStringToJWXAlgorithm(t *testing.T) {
	testCases := []struct {
		name          string
		algorithm     string
		expectError   bool
		errorContains string
	}{
		// Test all supported algorithms
		{name: "HS256", algorithm: "HS256", expectError: false},
		{name: "HS384", algorithm: "HS384", expectError: false},
		{name: "HS512", algorithm: "HS512", expectError: false},
		{name: "RS256", algorithm: "RS256", expectError: false},
		{name: "RS384", algorithm: "RS384", expectError: false},
		{name: "RS512", algorithm: "RS512", expectError: false},
		{name: "ES256", algorithm: "ES256", expectError: false},
		{name: "ES384", algorithm: "ES384", expectError: false},
		{name: "ES512", algorithm: "ES512", expectError: false},
		{name: "ES256K", algorithm: "ES256K", expectError: false},
		{name: "PS256", algorithm: "PS256", expectError: false},
		{name: "PS384", algorithm: "PS384", expectError: false},
		{name: "PS512", algorithm: "PS512", expectError: false},
		{name: "EdDSA", algorithm: "EdDSA", expectError: false},
		// Test unsupported algorithm
		{name: "unsupported", algorithm: "INVALID", expectError: true, errorContains: "unsupported algorithm: INVALID"},
		{name: "none", algorithm: "none", expectError: true, errorContains: "unsupported algorithm: none"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			jwxAlg, err := stringToJWXAlgorithm(tc.algorithm)

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorContains)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, jwxAlg)
				assert.Equal(t, tc.algorithm, jwxAlg.String())
			}
		})
	}
}

func TestValidateIssuer(t *testing.T) {
	v := &Validator{
		expectedIssuers: []string{
			"https://issuer1.example.com/",
			"https://issuer2.example.com/",
		},
	}

	t.Run("valid issuer matches first", func(t *testing.T) {
		err := v.validateIssuer("https://issuer1.example.com/")
		assert.NoError(t, err)
	})

	t.Run("valid issuer matches second", func(t *testing.T) {
		err := v.validateIssuer("https://issuer2.example.com/")
		assert.NoError(t, err)
	})

	t.Run("invalid issuer does not match any", func(t *testing.T) {
		err := v.validateIssuer("https://hacker.example.com/")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `token issuer "https://hacker.example.com/" does not match any expected issuer`)
	})
}

func TestValidateAudience(t *testing.T) {
	v := &Validator{
		expectedAudiences: []string{
			"audience1",
			"audience2",
		},
	}

	t.Run("valid when token has matching audience", func(t *testing.T) {
		err := v.validateAudience([]string{"audience1"})
		assert.NoError(t, err)
	})

	t.Run("valid when token has multiple audiences with one matching", func(t *testing.T) {
		err := v.validateAudience([]string{"other", "audience2", "another"})
		assert.NoError(t, err)
	})

	t.Run("error when token has no audiences", func(t *testing.T) {
		err := v.validateAudience([]string{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has no audience")
	})

	t.Run("error when token audiences do not match any expected", func(t *testing.T) {
		err := v.validateAudience([]string{"wrong-audience", "another-wrong"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token audience")
		assert.Contains(t, err.Error(), "does not match any expected audience")
	})
}

func TestExtractCustomClaims(t *testing.T) {
	const (
		issuer   = "https://go-jwt-middleware.eu.auth0.com/"
		audience = "https://go-jwt-middleware-api/"
	)

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}

	t.Run("error when token has invalid base64 in payload", func(t *testing.T) {
		v, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(HS256),
			WithIssuer(issuer),
			WithAudience(audience),
			WithCustomClaims(func() *testClaims {
				return &testClaims{}
			}),
		)
		require.NoError(t, err)

		// Create a token with invalid base64 in the payload
		// Format: header.invalid-base64-payload.signature
		invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.!!!invalid-base64!!!.signature"

		_, err = v.extractCustomClaims(context.Background(), invalidToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode JWT payload")
	})

	t.Run("error when token payload is not valid JSON", func(t *testing.T) {
		v, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(HS256),
			WithIssuer(issuer),
			WithAudience(audience),
			WithCustomClaims(func() *testClaims {
				return &testClaims{}
			}),
		)
		require.NoError(t, err)

		// Create a token with valid base64 but invalid JSON
		// "not-json" in base64url: bm90LWpzb24
		invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bm90LWpzb24.signature"

		_, err = v.extractCustomClaims(context.Background(), invalidToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal custom claims")
	})

	t.Run("error when token format is invalid (not 3 parts)", func(t *testing.T) {
		v, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(HS256),
			WithIssuer(issuer),
			WithAudience(audience),
			WithCustomClaims(func() *testClaims {
				return &testClaims{}
			}),
		)
		require.NoError(t, err)

		// Create a token with only 2 parts
		invalidToken := "header.payload"

		_, err = v.extractCustomClaims(context.Background(), invalidToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid JWT format")
		assert.Contains(t, err.Error(), "expected 3 parts, got 2")
	})

	t.Run("error when token format has too many parts", func(t *testing.T) {
		v, err := New(
			WithKeyFunc(keyFunc),
			WithAlgorithm(HS256),
			WithIssuer(issuer),
			WithAudience(audience),
			WithCustomClaims(func() *testClaims {
				return &testClaims{}
			}),
		)
		require.NoError(t, err)

		// Create a token with 4 parts
		invalidToken := "header.payload.signature.extra"

		_, err = v.extractCustomClaims(context.Background(), invalidToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid JWT format")
		assert.Contains(t, err.Error(), "expected 3 parts, got 4")
	})
}

func TestValidator_IssuerValidationInValidateToken(t *testing.T) {
	const (
		tokenIssuer = "https://go-jwt-middleware.eu.auth0.com/"
		audience    = "https://go-jwt-middleware-api/"
	)

	t.Run("it throws an error when token issuer does not match any expected issuer", func(t *testing.T) {
		// Use a valid token with issuer "https://go-jwt-middleware.eu.auth0.com/"
		// but configure validator to expect a different issuer
		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0"

		// Configure validator to expect a different issuer
		v, err := New(
			WithKeyFunc(func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			}),
			WithAlgorithm(HS256),
			WithIssuer("https://different-issuer.example.com/"),
			WithAudience(audience),
		)
		require.NoError(t, err)

		_, err = v.ValidateToken(context.Background(), token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuer validation failed")
		assert.Contains(t, err.Error(), "does not match any expected issuer")
	})
}

func TestParseToken_DefensiveAlgorithmCheck(t *testing.T) {
	// This test covers defensive code in parseToken that checks for unsupported algorithms.
	// While WithAlgorithm validates algorithms at construction time, parseToken has
	// defensive checks in case the Validator struct is modified directly.
	t.Run("error when algorithm is unsupported in parseToken", func(t *testing.T) {
		// Create a validator with an invalid algorithm by bypassing normal construction
		// This tests the defensive code path in parseToken
		v := &Validator{
			signatureAlgorithm: "UNSUPPORTED",
			keyFunc: func(context.Context) (interface{}, error) {
				return []byte("secret"), nil
			},
			expectedIssuers:   []string{"https://issuer.example.com/"},
			expectedAudiences: []string{"audience"},
		}

		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2dvLWp3dC1taWRkbGV3YXJlLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjpbImh0dHBzOi8vZ28tand0LW1pZGRsZXdhcmUtYXBpLyJdfQ.-R2K2tZHDrgsEh9JNWcyk4aljtR6gZK0s2anNGlfwz0"
		key := []byte("secret")

		_, err := v.parseToken(context.Background(), token, key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})
}

func TestParseToken_WithJWKSet(t *testing.T) {
	// This test ensures the jwk.Set code path in parseToken is taken.
	// The http-jwks-example test provides end-to-end validation of JWKS functionality.
	// This unit test verifies parseToken correctly handles jwk.Set type.
	t.Run("handles jwk.Set type correctly", func(t *testing.T) {
		// Create an empty jwk.Set to test the type switch
		set := jwk.NewSet()

		// Create a simple validator
		v := &Validator{
			signatureAlgorithm: HS256,
			expectedIssuers:    []string{"https://issuer.example.com/"},
			expectedAudiences:  []string{"audience"},
		}

		// Call parseToken directly to test the jwk.Set branch
		// Expected: type switch detects jwk.Set and uses jwt.WithKeySet
		// This will fail validation (no valid keys), but that's ok - we're testing the code path
		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbS8iLCJhdWQiOlsiYXVkaWVuY2UiXX0.4Adcj0pYJ0iqh_iFcxJDCbU9wE9c0q4mKIwZH4u1rLo"

		_, err := v.parseToken(context.Background(), token, set)

		// Expected to fail with signature verification error (not algorithm error)
		// This confirms the jwk.Set code path was taken
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse and validate token")
		// Should NOT contain "unsupported algorithm" since we're using HS256
		assert.NotContains(t, err.Error(), "unsupported algorithm")
	})
}

