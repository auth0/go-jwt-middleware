package jwtmiddleware

import (
	"context"
	"errors"
	"fmt"
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
		validToken   = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwiYXVkIjoidGVzdEF1ZGllbmNlIn0.Bg8HXYXZ13zaPAcB0Bl0kRKW0iVF-2LTmITcEYUcWoo"
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

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
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
		path           string
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
			name: "it calls the custom error handler when token validation fails",
			options: []Option{
				WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write(fmt.Appendf(nil, `{"message":"Custom error: %s"}`, err.Error()))
				}),
			},
			validateToken: func(context.Context, string) (interface{}, error) {
				return nil, errors.New("token validation failed")
			},
			token:          "invalid_token",
			method:         http.MethodGet,
			wantStatusCode: http.StatusForbidden,
			wantBody:       `{"message":"Custom error: error extracting token: Authorization header format must be Bearer {token}"}`,
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
		{
			name: "JWT not required for /public",
			options: []Option{
				WithExclusionUrls([]string{"/public", "/health", "/special"}),
			},
			method:         http.MethodGet,
			path:           "/public",
			token:          "",
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "JWT not required for /health",
			options: []Option{
				WithExclusionUrls([]string{"/public", "/health", "/special"}),
			},
			method:         http.MethodGet,
			path:           "/health",
			token:          "",
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "JWT not required for /special",
			options: []Option{
				WithExclusionUrls([]string{"/public", "/health", "/special"}),
			},
			method:         http.MethodGet,
			path:           "/special",
			token:          "",
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "JWT required for /secure (not in exclusion list)",
			options: []Option{
				WithExclusionUrls([]string{"/public", "/health", "/special"}),
			},
			method:         http.MethodGet,
			path:           "/secure",
			token:          "",
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing."}`,
		},
		{
			name: "JWT not required for /custom_exclusion using WithExclusionUrlHandler",
			options: []Option{
				WithExclusionUrlHandler(func(r *http.Request) bool {
					return r.URL.Path == "/custom_exclusion"
				}),
			},
			method:         http.MethodGet,
			path:           "/custom_exclusion",
			token:          "",
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "JWT required for /not_excluded using WithExclusionUrlHandler",
			options: []Option{
				WithExclusionUrlHandler(func(r *http.Request) bool {
					return r.URL.Path == "/custom_exclusion"
				}),
			},
			method:         http.MethodGet,
			path:           "/not_excluded",
			token:          "",
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing."}`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
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

			url := testServer.URL + testCase.path
			request, err := http.NewRequest(testCase.method, url, nil)
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
