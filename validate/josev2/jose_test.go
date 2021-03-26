package josev2

import (
	"errors"
	"testing"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type testingCustomClaims struct {
	Subject     string
	ReturnError error
}

func (tcc *testingCustomClaims) Validate() error {
	return tcc.ReturnError
}

func Test_Validate(t *testing.T) {
	testCases := []struct {
		name               string
		signatureAlgorithm jose.SignatureAlgorithm
		token              string
		keyFuncReturnError error
		customClaims       CustomClaims
		expectedClaims     jwt.Expected
		expectedError      error
	}{
		{
			name:  "happy path",
			token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
		},
		{
			// we want to test that when it expects RSA but we send
			// HMAC encrypted with the server public key it will
			// error
			name:               "errors on wrong algorithm",
			signatureAlgorithm: jose.PS256,
			token:              `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
			expectedError:      errors.New("expected \"PS256\" signin algorithm but token specified \"HS256\""),
		},
		{
			name:          "errors when jwt.ParseSigned errors",
			expectedError: errors.New("could not parse the token: square/go-jose: compact JWS format must have three parts"),
		},
		{
			name:               "errors when the key func errors",
			token:              `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
			keyFuncReturnError: errors.New("key func error message"),
			expectedError:      errors.New("error getting the keys from the key func: key func error message"),
		},
		{
			name:          "errors when tok.Claims errors",
			token:         `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hDyICUnkCrwFJnkJHRSkwMZNSYZ9LI6z2EFJdtwFurA`,
			expectedError: errors.New("could not get token claims: square/go-jose: error in cryptographic primitive"),
		},
		{
			name:           "errors when expected claims errors",
			token:          `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
			expectedClaims: jwt.Expected{Subject: "wrong subject"},
			expectedError:  errors.New("expected claims not validated: square/go-jose/jwt: validation failed, invalid subject claim (sub)"),
		},
		{
			name:          "errors when custom claims errors",
			token:         `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`,
			customClaims:  &testingCustomClaims{ReturnError: errors.New("custom claims error message")},
			expectedError: errors.New("custom claims not validated: custom claims error message"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var customClaimsFunc func() CustomClaims = nil
			if testCase.customClaims != nil {
				customClaimsFunc = func() CustomClaims { return testCase.customClaims }
			}

			v := New(func() (interface{}, error) { return []byte("secret"), testCase.keyFuncReturnError },
				testCase.signatureAlgorithm,
				func() jwt.Expected { return testCase.expectedClaims },
				WithCustomClaims(customClaimsFunc),
			)
			_, err := v.ValidateToken(testCase.token)
			if testCase.expectedError == nil && err != nil {
				t.Fatalf("did not expect an error, but got %q", err.Error())
			} else if testCase.expectedError != nil {
				if err == nil {
					t.Fatal("expected to get an error but did not get one")
				}
				if testCase.expectedError.Error() != err.Error() {
					t.Fatalf("did not get the expected error %q,\nbut instead got %q", testCase.expectedError.Error(), err.Error())
				}
			}
		})
	}
}
