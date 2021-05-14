package jwtmiddleware

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// defaults tests against the default setup
// TODO(joncarl): replace with actual JWTs once we have the validate stuff plumbed in
func Test_defaults(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		method  string
		token   string

		wantToken      map[string]string
		wantStatusCode int
		wantBody       string
	}{
		{
			name: "happy path",
			options: []Option{WithValidateToken(func(token string) (interface{}, error) {
				return map[string]string{"foo": "bar"}, nil
			})},
			token:          "bearer abc",
			wantToken:      map[string]string{"foo": "bar"},
			wantStatusCode: http.StatusOK,
			wantBody:       "authenticated",
		},
		{
			name: "validate on options",
			options: []Option{WithValidateToken(func(token string) (interface{}, error) {
				return map[string]string{"foo": "bar"}, nil
			})},
			method:         http.MethodOptions,
			token:          "bearer abc",
			wantToken:      map[string]string{"foo": "bar"},
			wantStatusCode: http.StatusOK,
			wantBody:       "authenticated",
		},
		{
			name: "bad token format",
			options: []Option{WithValidateToken(func(token string) (interface{}, error) {
				return map[string]string{"foo": "bar"}, nil
			})},
			token:          "abc",
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "credentials not optional",
			options: []Option{WithValidateToken(func(token string) (interface{}, error) {
				return map[string]string{"foo": "bar"}, nil
			})},
			token:          "",
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "validate token errors",
			options: []Option{WithValidateToken(func(token string) (interface{}, error) {
				return nil, errors.New("validate token error")
			})},
			token:          "bearer abc",
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name: "validateOnOptions set to false",
			options: []Option{
				WithValidateOnOptions(false),
				WithValidateToken(func(token string) (interface{}, error) {
					return nil, errors.New("should not hit me since we are not validating on options")
				}),
			},
			method:         http.MethodOptions,
			token:          "bearer abc",
			wantStatusCode: http.StatusOK,
			wantBody:       "authenticated",
		},
		{
			name: "tokenExtractor errors",
			options: []Option{WithTokenExtractor(func(r *http.Request) (string, error) {
				return "", errors.New("token extractor error")
			})},
			wantStatusCode: http.StatusInternalServerError,
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
			wantStatusCode: http.StatusOK,
			wantBody:       "authenticated",
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
			wantStatusCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var actualContextToken map[string]string

			if tc.method == "" {
				tc.method = http.MethodGet
			}

			m := New(tc.options...)
			ts := httptest.NewServer(m.CheckJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ctxToken, ok := r.Context().Value(ContextKey{}).(map[string]string); ok {
					actualContextToken = ctxToken
				}
				fmt.Fprint(w, "authenticated")
			})))
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

			if want, got := tc.wantStatusCode, res.StatusCode; want != got {
				t.Fatalf("want status code %d, got %d", want, got)
			}

			if want, got := tc.wantBody, string(body); !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}

			if want, got := tc.wantToken, actualContextToken; !cmp.Equal(want, got) {
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
			gotToken, gotError := AuthHeaderTokenExtractor(tc.request)
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
