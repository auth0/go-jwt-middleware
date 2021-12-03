package jwtmiddleware

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
)

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
