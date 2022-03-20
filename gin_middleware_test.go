package jwtmiddleware

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v2/validator"
)

func Test_GinCheckJWT(t *testing.T) {
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
		options        []GinOption
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
			options: []GinOption{
				GinWithValidateOnOptions(false),
			},
			method:         http.MethodOptions,
			token:          validToken,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "it fails validation if there are errors with the token extractor",
			options: []GinOption{
				GinWithTokenExtractor(func(r *http.Request) (string, error) {
					return "", errors.New("token extractor error")
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusInternalServerError,
			wantBody:       `{"message":"Something went wrong while checking the JWT."}`,
		},
		{
			name: "credentialsOptional true",
			options: []GinOption{
				GinWithCredentialsOptional(true),
				GinWithTokenExtractor(func(r *http.Request) (string, error) {
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
			options: []GinOption{
				GinWithCredentialsOptional(false),
				GinWithTokenExtractor(func(r *http.Request) (string, error) {
					return "", nil
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing."}`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			middleware := NewGin(testCase.validateToken, testCase.options...)

			var actualValidatedClaims interface{}
			var handler gin.HandlerFunc = gin.HandlerFunc(func(c *gin.Context) {
				actualValidatedClaims = c.Request.Context().Value(ContextKey{})
				c.JSON(http.StatusOK, gin.H{
					"message": "Authenticated.",
				})
			})

			// testServer := httptest.NewServer(middleware.CheckJWTGin())
			gin.SetMode(gin.TestMode)
			ginServer := gin.New()
			ginServer.Use(middleware.CheckJWTGin())
			ginServer.Handle(testCase.method, "", handler)
			testServer := httptest.NewServer(ginServer)

			request, err := http.NewRequest(testCase.method, testServer.URL, nil)
			require.NoError(t, err)
			if testCase.token != "" {
				request.Header.Add("Authorization", testCase.token)
			}
			response, err := testServer.Client().Do(request)
			require.NoError(t, err)

			body, err := ioutil.ReadAll(response.Body)
			require.NoError(t, err)
			defer response.Body.Close()

			assert.Equal(t, testCase.wantStatusCode, response.StatusCode)
			assert.Equal(t, "application/json; charset=utf-8", response.Header.Get("Content-Type"))
			assert.Equal(t, testCase.wantBody, string(body))

			if want, got := testCase.wantToken, actualValidatedClaims; !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}
		})
	}
}
