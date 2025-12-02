package jwtmiddleware

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AuthHeaderTokenExtractor(t *testing.T) {
	testCases := []struct {
		name       string
		request    *http.Request
		wantToken  string
		wantScheme AuthScheme
		wantError  string
	}{
		{
			name:       "empty / no header",
			request:    &http.Request{},
			wantScheme: AuthSchemeUnknown,
		},
		{
			name: "token in header",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer i-am-a-token"},
				},
			},
			wantToken:  "i-am-a-token",
			wantScheme: AuthSchemeBearer,
		},
		{
			name: "no bearer",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"i-am-a-token"},
				},
			},
			wantError: "authorization header format must be Bearer {token} or DPoP {token}",
		},
		{
			name: "bearer with uppercase",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"BEARER i-am-a-token"},
				},
			},
			wantToken:  "i-am-a-token",
			wantScheme: AuthSchemeBearer,
		},
		{
			name: "bearer with mixed case",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"BeArEr i-am-a-token"},
				},
			},
			wantToken:  "i-am-a-token",
			wantScheme: AuthSchemeBearer,
		},
		{
			name: "multiple spaces between bearer and token",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer    i-am-a-token"},
				},
			},
			wantToken:  "i-am-a-token",
			wantScheme: AuthSchemeBearer,
		},
		{
			name: "extra parts after token",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer token extra-part"},
				},
			},
			wantError: "authorization header format must be Bearer {token} or DPoP {token}",
		},
		{
			name: "DPoP scheme with token",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"DPoP i-am-a-dpop-token"},
				},
			},
			wantToken:  "i-am-a-dpop-token",
			wantScheme: AuthSchemeDPoP,
		},
		{
			name: "DPoP scheme with uppercase",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"DPOP i-am-a-dpop-token"},
				},
			},
			wantToken:  "i-am-a-dpop-token",
			wantScheme: AuthSchemeDPoP,
		},
		{
			name: "DPoP scheme with mixed case",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"DpOp i-am-a-dpop-token"},
				},
			},
			wantToken:  "i-am-a-dpop-token",
			wantScheme: AuthSchemeDPoP,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result, err := AuthHeaderTokenExtractor(testCase.request)
			if testCase.wantError != "" {
				assert.EqualError(t, err, testCase.wantError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.wantToken, result.Token)
				assert.Equal(t, testCase.wantScheme, result.Scheme)
			}
		})
	}
}

func Test_ParameterTokenExtractor(t *testing.T) {
	t.Run("extracts token from query parameter", func(t *testing.T) {
		wantToken := "i am a token"
		param := "i-am-param"

		testURL, err := url.Parse(fmt.Sprintf("http://localhost?%s=%s", param, wantToken))
		require.NoError(t, err)

		request := &http.Request{URL: testURL}
		tokenExtractor := ParameterTokenExtractor(param)

		result, err := tokenExtractor(request)
		require.NoError(t, err)

		assert.Equal(t, wantToken, result.Token)
		assert.Equal(t, AuthSchemeUnknown, result.Scheme)
	})

	t.Run("returns error for empty parameter name", func(t *testing.T) {
		testURL, err := url.Parse("http://localhost?token=abc")
		require.NoError(t, err)

		request := &http.Request{URL: testURL}
		tokenExtractor := ParameterTokenExtractor("")

		result, err := tokenExtractor(request)
		assert.EqualError(t, err, "parameter name cannot be empty")
		assert.Empty(t, result.Token)
	})
}

func Test_CookieTokenExtractor(t *testing.T) {
	testCases := []struct {
		name       string
		cookie     *http.Cookie
		wantToken  string
		wantScheme AuthScheme
		wantError  string
	}{
		{
			name:       "no cookie",
			cookie:     nil,
			wantToken:  "",
			wantScheme: AuthSchemeUnknown,
		},
		{
			name:       "cookie has a token",
			cookie:     &http.Cookie{Name: "token", Value: "i-am-a-token"},
			wantToken:  "i-am-a-token",
			wantScheme: AuthSchemeUnknown,
		},
		{
			name:       "cookie has no token",
			cookie:     &http.Cookie{Name: "token"},
			wantToken:  "",
			wantScheme: AuthSchemeUnknown,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)

			if testCase.cookie != nil {
				request.AddCookie(testCase.cookie)
			}

			result, err := CookieTokenExtractor("token")(request)
			if testCase.wantError != "" {
				assert.EqualError(t, err, testCase.wantError)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, testCase.wantToken, result.Token)
			assert.Equal(t, testCase.wantScheme, result.Scheme)
		})
	}

	t.Run("returns error for empty cookie name", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)

		result, err := CookieTokenExtractor("")(request)
		assert.EqualError(t, err, "cookie name cannot be empty")
		assert.Empty(t, result.Token)
	})
}

func Test_MultiTokenExtractor(t *testing.T) {
	noopExtractor := func(r *http.Request) (ExtractedToken, error) {
		return ExtractedToken{}, nil
	}
	extractor := func(r *http.Request) (ExtractedToken, error) {
		return ExtractedToken{Scheme: AuthSchemeBearer, Token: "i am a token"}, nil
	}
	erringExtractor := func(r *http.Request) (ExtractedToken, error) {
		return ExtractedToken{}, errors.New("extraction failure")
	}

	t.Run("it uses the first extractor that replies", func(t *testing.T) {
		wantToken := "i am a token"

		tokenExtractor := MultiTokenExtractor(noopExtractor, extractor, erringExtractor)

		result, err := tokenExtractor(&http.Request{})
		require.NoError(t, err)

		assert.Equal(t, wantToken, result.Token)
		assert.Equal(t, AuthSchemeBearer, result.Scheme)
	})

	t.Run("it stops when an extractor fails", func(t *testing.T) {
		wantErr := "extraction failure"

		tokenExtractor := MultiTokenExtractor(noopExtractor, erringExtractor)

		result, err := tokenExtractor(&http.Request{})

		assert.EqualError(t, err, wantErr)
		assert.Empty(t, result.Token)
	})

	t.Run("it defaults to empty", func(t *testing.T) {
		tokenExtractor := MultiTokenExtractor(noopExtractor, noopExtractor, noopExtractor)

		result, err := tokenExtractor(&http.Request{})
		require.NoError(t, err)

		assert.Empty(t, result.Token)
	})
}

// TestCookieTokenExtractor_EdgeCases tests edge cases for cookie extractor
func TestCookieTokenExtractor_EdgeCases(t *testing.T) {
	t.Run("empty cookie name returns error", func(t *testing.T) {
		extractor := CookieTokenExtractor("")
		req := &http.Request{}

		result, err := extractor(req)

		assert.Empty(t, result.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cookie name")
	})

	t.Run("missing cookie returns empty token", func(t *testing.T) {
		extractor := CookieTokenExtractor("auth-token")
		req := &http.Request{
			Header: http.Header{},
		}

		result, err := extractor(req)

		assert.Empty(t, result.Token)
		assert.NoError(t, err)
	})

	t.Run("cookie with value returns token", func(t *testing.T) {
		extractor := CookieTokenExtractor("auth-token")
		req := &http.Request{
			Header: http.Header{
				"Cookie": []string{"auth-token=test-token-value"},
			},
		}

		result, err := extractor(req)

		assert.Equal(t, "test-token-value", result.Token)
		assert.Equal(t, AuthSchemeUnknown, result.Scheme)
		assert.NoError(t, err)
	})
}

// TestMultiTokenExtractor_EdgeCases tests edge cases for multi-token extractor
func TestMultiTokenExtractor_EdgeCases(t *testing.T) {
	t.Run("empty extractors returns empty", func(t *testing.T) {
		extractor := MultiTokenExtractor()
		req := &http.Request{}

		result, err := extractor(req)

		assert.Empty(t, result.Token)
		assert.NoError(t, err)
	})

	t.Run("first extractor returns error, stops", func(t *testing.T) {
		testError := errors.New("extraction failed")
		extractor := MultiTokenExtractor(
			func(r *http.Request) (ExtractedToken, error) {
				return ExtractedToken{}, testError
			},
			func(r *http.Request) (ExtractedToken, error) {
				return ExtractedToken{Scheme: AuthSchemeBearer, Token: "should-not-be-called"}, nil
			},
		)
		req := &http.Request{}

		result, err := extractor(req)

		assert.Empty(t, result.Token)
		require.Error(t, err)
		assert.Equal(t, testError, err)
	})

	t.Run("second extractor returns token after first is empty", func(t *testing.T) {
		extractor := MultiTokenExtractor(
			func(r *http.Request) (ExtractedToken, error) {
				return ExtractedToken{}, nil
			},
			func(r *http.Request) (ExtractedToken, error) {
				return ExtractedToken{Scheme: AuthSchemeBearer, Token: "found-token"}, nil
			},
		)
		req := &http.Request{}

		result, err := extractor(req)

		assert.Equal(t, "found-token", result.Token)
		assert.Equal(t, AuthSchemeBearer, result.Scheme)
		assert.NoError(t, err)
	})
}

// TestAuthHeaderTokenExtractorWithScheme tests the scheme-aware token extractor
func TestAuthHeaderTokenExtractorWithScheme(t *testing.T) {
	testCases := []struct {
		name       string
		request    *http.Request
		wantToken  string
		wantScheme AuthScheme
		wantError  string
	}{
		{
			name:       "empty / no header returns empty result",
			request:    &http.Request{},
			wantToken:  "",
			wantScheme: AuthSchemeUnknown,
		},
		{
			name: "Bearer scheme extracts token and scheme",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer i-am-a-token"},
				},
			},
			wantToken:  "i-am-a-token",
			wantScheme: AuthSchemeBearer,
		},
		{
			name: "DPoP scheme extracts token and scheme",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"DPoP i-am-a-dpop-token"},
				},
			},
			wantToken:  "i-am-a-dpop-token",
			wantScheme: AuthSchemeDPoP,
		},
		{
			name: "Bearer scheme case insensitive",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"BEARER mixed-case-token"},
				},
			},
			wantToken:  "mixed-case-token",
			wantScheme: AuthSchemeBearer,
		},
		{
			name: "DPoP scheme case insensitive",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"dpop lowercase-dpop-token"},
				},
			},
			wantToken:  "lowercase-dpop-token",
			wantScheme: AuthSchemeDPoP,
		},
		{
			name: "unsupported scheme returns error",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Basic dXNlcjpwYXNz"},
				},
			},
			wantError: "authorization header format must be Bearer {token} or DPoP {token}",
		},
		{
			name: "malformed header returns error",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"just-a-token"},
				},
			},
			wantError: "authorization header format must be Bearer {token} or DPoP {token}",
		},
		{
			name: "extra parts after token returns error",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer token extra-part"},
				},
			},
			wantError: "authorization header format must be Bearer {token} or DPoP {token}",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result, err := AuthHeaderTokenExtractor(testCase.request)
			if testCase.wantError != "" {
				assert.EqualError(t, err, testCase.wantError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.wantToken, result.Token)
				assert.Equal(t, testCase.wantScheme, result.Scheme)
			}
		})
	}
}
