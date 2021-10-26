package jwtmiddleware

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/auth0/go-jwt-middleware/validate/josev2"
)

func Test_CheckJWT(t *testing.T) {
	var (
		validToken        = "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0aW5nIn0.SdU_8KjnZsQChrVtQpYGxS48DxB4rTM9biq6D4haR70"
		invalidToken      = "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0aW5nIn0.eM1Jd7VA7nFSI09FlmLmtuv7cLnv8qicZ8s76-jTOoE"
		validContextToken = &josev2.UserContext{
			Claims: jwt.Claims{
				Issuer: "testing",
			},
		}
	)

	validator, err := josev2.New(
		func(_ context.Context) (interface{}, error) {
			return []byte("secret"), nil
		},
		jose.HS256,
		josev2.WithExpectedClaims(
			func() jwt.Expected {
				return jwt.Expected{Issuer: "testing"}
			},
		),
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
			validateToken:  validator.ValidateToken,
			token:          validToken,
			wantToken:      validContextToken,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name:           "validate on options",
			validateToken:  validator.ValidateToken,
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
		},
		{
			name:           "credentials not optional",
			token:          "",
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "validate token errors",
			validateToken:  validator.ValidateToken,
			token:          invalidToken,
			wantStatusCode: http.StatusUnauthorized,
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
				w.Write([]byte(`{"message":"Authenticated."}`))
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

			if want, got := testCase.wantBody, string(body); !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}

			if want, got := testCase.wantToken, actualContextToken; !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}
		})
	}

}

func Test_invalidError(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		e := invalidError{details: errors.New("error details")}

		if !errors.Is(&e, ErrJWTInvalid) {
			t.Fatal("expected invalidError to be ErrJWTInvalid via errors.Is, but it was not")
		}
	})

	t.Run("Error", func(t *testing.T) {
		e := invalidError{details: errors.New("error details")}

		mustErrorMsg(t, "jwt invalid: error details", &e)
	})

	t.Run("Unwrap", func(t *testing.T) {
		expectedErr := errors.New("expected err")
		e := invalidError{details: expectedErr}

		// under the hood errors.Is is unwrapping the invalidError via
		// Unwrap().
		if !errors.Is(&e, expectedErr) {
			t.Fatal("expected invalidError to be expectedErr via errors.Is, but it was not")
		}
	})
}

func Test_MultiTokenExtractor(t *testing.T) {
	t.Run("uses first extractor that replies", func(t *testing.T) {
		wantToken := "i am token"

		exNothing := func(r *http.Request) (string, error) {
			return "", nil
		}
		exSomething := func(r *http.Request) (string, error) {
			return wantToken, nil
		}
		exFail := func(r *http.Request) (string, error) {
			return "", errors.New("should not have hit me")
		}

		ex := MultiTokenExtractor(exNothing, exSomething, exFail)

		gotToken, err := ex(&http.Request{})
		mustErrorMsg(t, "", err)

		if wantToken != gotToken {
			t.Fatalf("wanted token: %q, got: %q", wantToken, gotToken)
		}
	})

	t.Run("stops when an extractor fails", func(t *testing.T) {
		wantErr := "extraction fail"

		exNothing := func(r *http.Request) (string, error) {
			return "", nil
		}
		exFail := func(r *http.Request) (string, error) {
			return "", errors.New(wantErr)
		}

		ex := MultiTokenExtractor(exNothing, exFail)

		gotToken, err := ex(&http.Request{})
		mustErrorMsg(t, wantErr, err)

		if gotToken != "" {
			t.Fatalf("did not want a token but got: %q", gotToken)
		}
	})

	t.Run("defaults to empty", func(t *testing.T) {
		exNothing := func(r *http.Request) (string, error) {
			return "", nil
		}

		ex := MultiTokenExtractor(exNothing, exNothing, exNothing)

		gotToken, err := ex(&http.Request{})
		mustErrorMsg(t, "", err)

		if "" != gotToken {
			t.Fatalf("wanted empty token but got: %q", gotToken)
		}
	})
}

func Test_ParameterTokenExtractor(t *testing.T) {
	wantToken := "i am token"
	param := "i-am-param"

	u, err := url.Parse(fmt.Sprintf("http://localhost?%s=%s", param, wantToken))
	mustErrorMsg(t, "", err)
	r := &http.Request{URL: u}

	ex := ParameterTokenExtractor(param)

	gotToken, err := ex(r)
	mustErrorMsg(t, "", err)

	if wantToken != gotToken {
		t.Fatalf("wanted token: %q, got: %q", wantToken, gotToken)
	}
}

func Test_AuthHeaderTokenExtractor(t *testing.T) {
	testCases := []struct {
		name      string
		request   *http.Request
		wantToken string
		wantError string
	}{
		{
			name:    "empty / no header",
			request: &http.Request{},
		},
		{
			name:      "token in header",
			request:   &http.Request{Header: http.Header{"Authorization": []string{fmt.Sprintf("Bearer %s", "i-am-token")}}},
			wantToken: "i-am-token",
		},
		{
			name:      "no bearer",
			request:   &http.Request{Header: http.Header{"Authorization": []string{"i-am-token"}}},
			wantError: "Authorization header format must be Bearer {token}",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotToken, gotError := AuthHeaderTokenExtractor(testCase.request)
			mustErrorMsg(t, testCase.wantError, gotError)

			if testCase.wantToken != gotToken {
				t.Fatalf("wanted token: %q, got: %q", testCase.wantToken, gotToken)
			}

		})
	}
}

func Test_CookieTokenExtractor(t *testing.T) {
	testCases := []struct {
		name      string
		cookie    *http.Cookie
		wantToken string
		wantError string
	}{
		{
			name:      "no cookie",
			wantError: "http: named cookie not present",
		},
		{
			name:      "token in cookie",
			cookie:    &http.Cookie{Name: "token", Value: "i-am-token"},
			wantToken: "i-am-token",
		},
		{
			name:   "empty cookie",
			cookie: &http.Cookie{Name: "token"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)

			if testCase.cookie != nil {
				req.AddCookie(testCase.cookie)
			}

			gotToken, gotError := CookieTokenExtractor("token")(req)
			mustErrorMsg(t, testCase.wantError, gotError)

			if testCase.wantToken != gotToken {
				t.Fatalf("wanted token: %q, got: %q", testCase.wantToken, gotToken)
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
