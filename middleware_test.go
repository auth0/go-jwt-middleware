package jwtmiddleware

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v2/validator"
)

func Test_CheckJWT(t *testing.T) {
	const (
		validToken   = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwiYXVkIjoidGVzdEF1ZGllbmNlIn0.Gyy_wLVaXohXo-QB1dgJWw-FbiS80mKw1OrTwmffvNo"
		invalidToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0aW5nIn0.eM1Jd7VA7nFSI09FlmLmtuv7cLnv8qicZ8s76-jTOoE"
		issuer       = "testIssuer"
		audience     = "testAudience"
	)

	tokenClaims := &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{
			Issuer:   issuer,
			Audience: []string{audience},
		},
	}

	secret := []byte("abcdefghijklmnopqrstuvwxyz012345")
	keyFunc := func(context.Context) (interface{}, error) {
		return secret, nil
	}

	jwtValidator, err := validator.New(keyFunc, validator.HS256, issuer, []string{audience})
	require.NoError(t, err)

	testCases := []struct {
		name           string
		validateToken  ValidateToken
		options        []Option
		method         string
		token          string
		wantToken      interface{}
		wantStatusCode int
		wantBody       string
	}{
		{
			name:           "it can successfully validate a token",
			validateToken:  jwtValidator.ValidateToken,
			token:          validToken,
			method:         http.MethodGet,
			wantToken:      tokenClaims,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name:           "it can validate on options",
			validateToken:  jwtValidator.ValidateToken,
			method:         http.MethodOptions,
			token:          validToken,
			wantToken:      tokenClaims,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name:           "it fails to validate a token with a bad format",
			token:          "bad",
			method:         http.MethodGet,
			wantStatusCode: http.StatusInternalServerError,
			wantBody:       `{"message":"Something went wrong while checking the JWT."}`,
		},
		{
			name:           "it fails to validate if token is missing and credentials are not optional",
			token:          "",
			method:         http.MethodGet,
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing."}`,
		},
		{
			name:           "it fails to validate an invalid token",
			validateToken:  jwtValidator.ValidateToken,
			token:          invalidToken,
			method:         http.MethodGet,
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"message":"JWT is invalid."}`,
		},
		{
			name: "it skips validation on OPTIONS if validateOnOptions is set to false",
			options: []Option{
				WithValidateOnOptions(false),
			},
			method:         http.MethodOptions,
			token:          validToken,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "it fails validation if there are errors with the token extractor",
			options: []Option{
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", errors.New("token extractor error")
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusInternalServerError,
			wantBody:       `{"message":"Something went wrong while checking the JWT."}`,
		},
		{
			name: "credentialsOptional true",
			options: []Option{
				WithCredentialsOptional(true),
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", nil
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "it fails validation if we do not receive any token from " +
				"a custom extractor and credentialsOptional is false",
			options: []Option{
				WithCredentialsOptional(false),
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", nil
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing."}`,
		},
	}

	for _, tC := range testCases {
		testCase := tC
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			middleware := New(testCase.validateToken, testCase.options...)

			var actualValidatedClaims interface{}
			var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actualValidatedClaims = r.Context().Value(ContextKey{})

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"Authenticated."}`))
			})

			testServer := httptest.NewServer(middleware.CheckJWT(handler))
			defer testServer.Close()

			request, err := http.NewRequest(testCase.method, testServer.URL, nil)
			require.NoError(t, err)

			if testCase.token != "" {
				request.Header.Add("Authorization", testCase.token)
			}

			response, err := testServer.Client().Do(request)
			require.NoError(t, err)

			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			defer response.Body.Close()

			assert.Equal(t, testCase.wantStatusCode, response.StatusCode)
			assert.Equal(t, "application/json", response.Header.Get("Content-Type"))
			assert.Equal(t, testCase.wantBody, string(body))

			if want, got := testCase.wantToken, actualValidatedClaims; !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}
		})
	}
}
