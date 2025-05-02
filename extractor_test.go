package jwtmiddleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

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
			name: "token in header",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer i-am-a-token"},
				},
			},
			wantToken: "i-am-a-token",
		},
		{
			name: "no bearer",
			request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"i-am-a-token"},
				},
			},
			wantError: "authorization header format must be 'Bearer {token}'",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			gotToken, err := AuthHeaderTokenExtractor(testCase.request)
			if testCase.wantError != "" {
				assert.EqualError(t, err, testCase.wantError)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, testCase.wantToken, gotToken)
		})
	}
}

func Test_ParameterTokenExtractor(t *testing.T) {
	wantToken := "i am a token"
	param := "i-am-param"

	testURL, err := url.Parse(fmt.Sprintf("http://localhost?%s=%s", param, wantToken))
	require.NoError(t, err)

	request := &http.Request{URL: testURL}
	tokenExtractor := ParameterTokenExtractor(param)

	gotToken, err := tokenExtractor(request)
	require.NoError(t, err)

	assert.Equal(t, wantToken, gotToken)
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
			cookie:    nil,
			wantToken: "",
		},
		{
			name:      "cookie has a token",
			cookie:    &http.Cookie{Name: "token", Value: "i-am-a-token"},
			wantToken: "i-am-a-token",
		},
		{
			name:      "cookie has no token",
			cookie:    &http.Cookie{Name: "token"},
			wantToken: "",
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

			gotToken, err := CookieTokenExtractor("token")(request)
			if testCase.wantError != "" {
				assert.EqualError(t, err, testCase.wantError)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, testCase.wantToken, gotToken)
		})
	}
}

func Test_MultiTokenExtractor(t *testing.T) {
	noopExtractor := func(r *http.Request) (string, error) {
		return "", nil
	}
	extractor := func(r *http.Request) (string, error) {
		return "i am a token", nil
	}
	erringExtractor := func(r *http.Request) (string, error) {
		return "", errors.New("extraction failure")
	}

	t.Run("it uses the first extractor that replies", func(t *testing.T) {
		wantToken := "i am a token"

		tokenExtractor := MultiTokenExtractor(noopExtractor, extractor, erringExtractor)

		gotToken, err := tokenExtractor(&http.Request{})
		require.NoError(t, err)

		assert.Equal(t, wantToken, gotToken)
	})

	t.Run("it stops when an extractor fails", func(t *testing.T) {
		wantErr := "extraction failure"

		tokenExtractor := MultiTokenExtractor(noopExtractor, erringExtractor)

		gotToken, err := tokenExtractor(&http.Request{})

		assert.EqualError(t, err, wantErr)
		assert.Empty(t, gotToken)
	})

	t.Run("it defaults to empty", func(t *testing.T) {
		tokenExtractor := MultiTokenExtractor(noopExtractor, noopExtractor, noopExtractor)

		gotToken, err := tokenExtractor(&http.Request{})
		require.NoError(t, err)

		assert.Empty(t, gotToken)
	})
}

func TestGRPCMetadataTokenExtractor(t *testing.T) {
	extractor := GRPCMetadataTokenExtractor()

	// Test case: Successful extraction with valid token
	t.Run("successful extraction", func(t *testing.T) {
		ctx := context.Background()
		md := metadata.New(map[string]string{
			"authorization": "Bearer test-token",
		})
		ctx = metadata.NewIncomingContext(ctx, md)
		req := &http.Request{}
		req = req.WithContext(ctx)

		token, err := extractor(req)
		assert.NoError(t, err)
		assert.Equal(t, "test-token", token)
	})

	// Test case: Missing metadata
	t.Run("missing metadata", func(t *testing.T) {
		req := &http.Request{}

		token, err := extractor(req)
		assert.Error(t, err)
		assert.Equal(t, "missing gRPC metadata in context", err.Error())
		assert.Equal(t, "", token)
	})

	// Test case: Missing authorization header
	t.Run("missing authorization header", func(t *testing.T) {
		ctx := context.Background()
		md := metadata.New(map[string]string{})
		ctx = metadata.NewIncomingContext(ctx, md)
		req := &http.Request{}
		req = req.WithContext(ctx)

		token, err := extractor(req)
		assert.Error(t, err)
		assert.Equal(t, "missing authorization header in gRPC metadata", err.Error())
		assert.Equal(t, "", token)
	})

	// Test case: Invalid authorization format
	t.Run("invalid authorization format", func(t *testing.T) {
		ctx := context.Background()
		md := metadata.New(map[string]string{
			"authorization": "InvalidFormat",
		})
		ctx = metadata.NewIncomingContext(ctx, md)
		req := &http.Request{}
		req = req.WithContext(ctx)

		token, err := extractor(req)
		assert.Error(t, err)
		assert.Equal(t, "authorization header format must be 'Bearer {token}'", err.Error())
		assert.Equal(t, "", token)
	})
}
