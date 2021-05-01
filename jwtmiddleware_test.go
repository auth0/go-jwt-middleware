package jwtmiddleware

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type testValidateToken struct {
	returnToken interface{}
	returnError error

	called   bool
	gotToken string
}

func (t *testValidateToken) validate(token string) (interface{}, error) {
	t.called = true
	t.gotToken = token

	return t.returnToken, t.returnError
}

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

			body, err := io.ReadAll(res.Body)
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

func mustErrorMsg(t testing.TB, want string, got error) {
	if (want == "" && got != nil) ||
		(want != "" && (got == nil || got.Error() != want)) {
		t.Fatalf("want error: %s, got %v", want, got)
	}
}

// To Test:
// FromFirst
// FromParameter
// FromAuthHeader
// Handler
// HandlerWithNext
