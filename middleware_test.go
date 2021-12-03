package jwtmiddleware

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"

	"github.com/auth0/go-jwt-middleware/validator"
)

func Test_CheckJWT(t *testing.T) {
	var (
		validToken        = "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0aW5nIn0.SdU_8KjnZsQChrVtQpYGxS48DxB4rTM9biq6D4haR70"
		invalidToken      = "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0aW5nIn0.eM1Jd7VA7nFSI09FlmLmtuv7cLnv8qicZ8s76-jTOoE"
		validContextToken = &validator.ValidatedClaims{
			RegisteredClaims: validator.RegisteredClaims{
				Issuer: "testing",
			},
		}
	)

	jwtValidator, err := validator.New(
		func(_ context.Context) (interface{}, error) {
			return []byte("secret"), nil
		},
		"HS256",
		"testing",
		[]string{},
	)
	if err != nil {
		t.Fatal(err)
	}

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
			name:           "happy path",
			validateToken:  jwtValidator.ValidateToken,
			token:          validToken,
			wantToken:      validContextToken,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name:           "validate on options",
			validateToken:  jwtValidator.ValidateToken,
			method:         http.MethodOptions,
			token:          validToken,
			wantToken:      validContextToken,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name:           "bad token format",
			token:          "bad",
			wantStatusCode: http.StatusInternalServerError,
			wantBody:       `{"message":"Something went wrong while checking the JWT."}`,
		},
		{
			name:           "credentials not optional",
			token:          "",
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing."}`,
		},
		{
			name:           "validate token errors",
			validateToken:  jwtValidator.ValidateToken,
			token:          invalidToken,
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"message":"JWT is invalid."}`,
		},
		{
			name: "validateOnOptions set to false",
			options: []Option{
				WithValidateOnOptions(false),
			},
			method:         http.MethodOptions,
			token:          validToken,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "tokenExtractor errors",
			options: []Option{
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", errors.New("token extractor error")
				}),
			},
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
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "credentialsOptional false",
			options: []Option{
				WithCredentialsOptional(false),
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", nil
				}),
			},
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing."}`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.method == "" {
				testCase.method = http.MethodGet
			}

			middleware := New(testCase.validateToken, testCase.options...)

			var actualContextToken interface{}
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actualContextToken = r.Context().Value(ContextKey{})

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"message":"Authenticated."}`))
			})

			testServer := httptest.NewServer(middleware.CheckJWT(testHandler))
			defer testServer.Close()

			request, err := http.NewRequest(testCase.method, testServer.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			if testCase.token != "" {
				request.Header.Add("Authorization", testCase.token)
			}

			response, err := testServer.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}

			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()

			if want, got := testCase.wantStatusCode, response.StatusCode; want != got {
				t.Fatalf("want status code %d, got %d", want, got)
			}

			if want, got := "application/json", response.Header.Get("Content-Type"); want != got {
				t.Fatalf("want Content-Type %s, got %s", want, got)
			}

			if want, got := testCase.wantBody, string(body); !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}

			if want, got := testCase.wantToken, actualContextToken; !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}
		})
	}
}

func mustErrorMsg(t testing.TB, want string, got error) {
	if (want == "" && got != nil) ||
		(want != "" && (got == nil || got.Error() != want)) {
		t.Fatalf("want error: %s, got %v", want, got)
	}
}
