package jwtmiddleware

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "authenticated")
})

// defaults tests against the default setup
// TODO(joncarl): replace with actual JWTs once we have the validate stuff plumbed in
func Test_defaults(t *testing.T) {
	tests := []struct {
		name   string
		method string
		token  string

		validateReturnError error

		expectStatusCode int
		expectBody       string
	}{
		{
			name:             "happy path",
			method:           http.MethodGet,
			token:            "bearer abc",
			expectStatusCode: http.StatusOK,
			expectBody:       "authenticated",
		},
		{
			name:             "validate on options",
			method:           http.MethodOptions,
			token:            "bearer abc",
			expectStatusCode: http.StatusOK,
			expectBody:       "authenticated",
		},
		{
			name:             "bad token format",
			method:           http.MethodGet,
			token:            "abc",
			expectStatusCode: http.StatusInternalServerError,
			expectBody:       "\n",
		},
		{
			name:             "credentials not optional",
			method:           http.MethodGet,
			token:            "",
			expectStatusCode: http.StatusBadRequest,
			expectBody:       "\n",
		},
		{
			name:                "validate token errors",
			method:              http.MethodGet,
			token:               "bearer abc",
			validateReturnError: errors.New("validate token error"),
			expectStatusCode:    http.StatusUnauthorized,
			expectBody:          "\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// TODO(joncarl): replace this with actual default validation setup
			m := New(WithValidateToken(func(token string) (interface{}, error) {
				return nil, tc.validateReturnError
			}))
			ts := httptest.NewServer(m.Handler(myHandler))
			defer ts.Close()

			client := ts.Client()
			req, _ := http.NewRequest(tc.method, ts.URL, nil)

			if len(tc.token) > 0 {
				req.Header.Add("Authorization", tc.token)
			}

			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tc.expectStatusCode {
				t.Fatalf("expected status code %d, but it was %d", tc.expectStatusCode, res.StatusCode)
			}

			if string(body) != tc.expectBody {
				t.Fatalf("expected body: %q, got: %q", tc.expectBody, body)
			}
		})
	}

}

type validToken struct {
	foo string
}

func Test_CheckJWT(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		method  string

		expectError string
		expectToken *validToken
	}{
		{
			name: "happy path: valid token",
			options: []Option{WithValidateToken(func(token string) (interface{}, error) {
				return &validToken{foo: "bar"}, nil
			})},
			expectToken: &validToken{foo: "bar"},
		},
		{
			name: "happy path: invalid token",
			options: []Option{WithValidateToken(func(token string) (interface{}, error) {
				return nil, errors.New("validate token error")
			})},
			expectError: "jwt invalid: validate token error",
		},
		{
			name: "validateOnOptions set to true",
			options: []Option{
				WithValidateOnOptions(true),
				WithValidateToken(func(token string) (interface{}, error) {
					return nil, errors.New("should hit me since it's validating on options")
				}),
			},
			method:      http.MethodOptions,
			expectError: "jwt invalid: should hit me since it's validating on options",
		},
		{
			name: "validateOnOptions set to false",
			options: []Option{
				WithValidateOnOptions(false),
				WithValidateToken(func(token string) (interface{}, error) {
					return nil, errors.New("should not hit me since we are not validating on options")
				}),
			},
			method: http.MethodOptions,
		},
		{
			name: "tokenExtractor errors",
			options: []Option{WithTokenExtractor(func(r *http.Request) (string, error) {
				return "", errors.New("token extractor error")
			})},
			expectError: "error extracting token: token extractor error",
		},
		{
			name: "credentialsOptional true",
			options: []Option{
				WithCredentialsOptional(true),
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", nil
				}),
				WithValidateToken(func(token string) (interface{}, error) {
					return nil, errors.New("should not hit me since credentials are optional and there are none")
				}),
			},
		},
		{
			name: "credentialsOptional false",
			options: []Option{
				WithCredentialsOptional(false),
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", nil
				}),
				WithValidateToken(func(token string) (interface{}, error) {
					return nil, errors.New("should not hit me since ErrJWTMissing should be returned")
				}),
			},
			expectError: ErrJWTMissing.Error(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defaultOptions := []Option{
				WithTokenExtractor(func(r *http.Request) (string, error) { return "asdf", nil }),
			}
			m := New(append(defaultOptions, tc.options...)...)

			req, _ := http.NewRequest(tc.method, "", nil)

			err := m.CheckJWT(req)

			mustErrorMsg(t, tc.expectError, err)

			var contextToken *validToken
			if v := req.Context().Value("user"); v != nil {
				contextToken = v.(*validToken)
			}
			if !reflect.DeepEqual(contextToken, tc.expectToken) {
				t.Fatalf("expected token in context: %+v\ngot: %+v", tc.expectToken, contextToken)
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

func Test_FromFirst(t *testing.T) {
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

		ex := FromFirst(exNothing, exSomething, exFail)

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

		ex := FromFirst(exNothing, exFail)

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

		ex := FromFirst(exNothing, exNothing, exNothing)

		gotToken, err := ex(&http.Request{})
		mustErrorMsg(t, "", err)

		if "" != gotToken {
			t.Fatalf("wanted empty token but got: %q", gotToken)
		}
	})
}

func Test_FromParameter(t *testing.T) {
	wantToken := "i am token"
	param := "i-am-param"

	u, err := url.Parse(fmt.Sprintf("http://localhost?%s=%s", param, wantToken))
	mustErrorMsg(t, "", err)
	r := &http.Request{URL: u}

	ex := FromParameter(param)

	gotToken, err := ex(r)
	mustErrorMsg(t, "", err)

	if wantToken != gotToken {
		t.Fatalf("wanted token: %q, got: %q", wantToken, gotToken)
	}
}

func Test_FromAuthHeader(t *testing.T) {
	tests := []struct {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotToken, gotError := FromAuthHeader(tc.request)
			mustErrorMsg(t, tc.wantError, gotError)

			if tc.wantToken != gotToken {
				t.Fatalf("wanted token: %q, got: %q", tc.wantToken, gotToken)
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
