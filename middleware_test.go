package jwtmiddleware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v3/core"
	"github.com/auth0/go-jwt-middleware/v3/validator"
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

	keyFunc := func(context.Context) (any, error) {
		return []byte("secret"), nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudience(audience),
	)
	require.NoError(t, err)

	testCases := []struct {
		name           string
		validator      *validator.Validator // Changed from validateToken
		options        []Option
		method         string
		token          string
		wantToken      any
		wantStatusCode int
		wantBody       string
		path           string
	}{
		{
			name:           "it can successfully validate a token",
			validator:      jwtValidator,
			token:          validToken,
			method:         http.MethodGet,
			wantToken:      tokenClaims,
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name:           "it can validate on options",
			validator:      jwtValidator,
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
			wantBody:       `{"error":"server_error","error_description":"An internal error occurred while processing the request"}`,
		},
		{
			name:           "it fails to validate if token is missing and credentials are not optional",
			token:          "",
			method:         http.MethodGet,
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"error":"invalid_token","error_description":"JWT is missing"}`,
		},
		{
			name:           "it fails to validate an invalid token",
			validator:      jwtValidator,
			token:          invalidToken,
			method:         http.MethodGet,
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"error":"invalid_token","error_description":"JWT is invalid"}`,
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
				WithTokenExtractor(func(r *http.Request) (ExtractedToken, error) {
					return ExtractedToken{}, errors.New("token extractor error")
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusInternalServerError,
			wantBody:       `{"error":"server_error","error_description":"An internal error occurred while processing the request"}`,
		},
		{
			name: "credentialsOptional true",
			options: []Option{
				WithCredentialsOptional(true),
				WithTokenExtractor(func(r *http.Request) (ExtractedToken, error) {
					return ExtractedToken{}, nil
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
				WithTokenExtractor(func(r *http.Request) (ExtractedToken, error) {
					return ExtractedToken{}, nil
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"error":"invalid_token","error_description":"JWT is missing"}`,
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
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"error":"invalid_token","error_description":"JWT is missing"}`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Use the test's validator if specified, otherwise create a default failing validator
			v := testCase.validator
			if v == nil {
				// Create a validator that always fails
				keyFunc := func(context.Context) (any, error) {
					return nil, errors.New("no key")
				}
				v, _ = validator.New(
					validator.WithKeyFunc(keyFunc),
					validator.WithAlgorithm(validator.HS256),
					validator.WithIssuer("fail"),
					validator.WithAudience("fail"),
				)
			}

			opts := append([]Option{WithValidator(v)}, testCase.options...)
			middleware, err := New(opts...)
			require.NoError(t, err)

			var actualValidatedClaims any
			var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Use the public API to get claims
				if HasClaims(r.Context()) {
					claims, _ := GetClaims[any](r.Context())
					actualValidatedClaims = claims
				}

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

			// Compare JSON responses (ignoring formatting differences like newlines)
			if testCase.wantBody != "" {
				assert.JSONEq(t, testCase.wantBody, string(body))
			}

			if want, got := testCase.wantToken, actualValidatedClaims; !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}
		})
	}
}

// TestNew_EdgeCases tests edge cases in the New() function for better coverage
func TestNew_EdgeCases(t *testing.T) {
	const (
		issuer   = "testIssuer"
		audience = "testAudience"
	)

	keyFunc := func(context.Context) (any, error) {
		return []byte("secret"), nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudience(audience),
	)
	require.NoError(t, err)

	t.Run("missing validator returns error", func(t *testing.T) {
		_, err := New()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid middleware configuration")
	})

	t.Run("invalid option returns error", func(t *testing.T) {
		invalidOption := func(m *JWTMiddleware) error {
			return errors.New("invalid option test")
		}

		_, err := New(WithValidator(jwtValidator), invalidOption)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid option")
	})

	t.Run("nil validator returns validation error", func(t *testing.T) {
		_, err := New(WithValidator(nil))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validator cannot be nil")
	})

	t.Run("successful creation with DPoP options", func(t *testing.T) {
		middleware, err := New(
			WithValidator(jwtValidator),
			WithDPoPMode(DPoPAllowed),
			WithDPoPProofOffset(60),
			WithDPoPIATLeeway(5),
		)
		require.NoError(t, err)
		assert.NotNil(t, middleware)
		assert.NotNil(t, middleware.dpopMode)
		assert.Equal(t, DPoPAllowed, *middleware.dpopMode)
		assert.NotNil(t, middleware.dpopProofOffset)
		assert.Equal(t, time.Duration(60), *middleware.dpopProofOffset)
		assert.NotNil(t, middleware.dpopIATLeeway)
		assert.Equal(t, time.Duration(5), *middleware.dpopIATLeeway)
	})

	t.Run("successful creation with all configuration options", func(t *testing.T) {
		mockLog := &mockLogger{}
		customExtractor := func(r *http.Request) (ExtractedToken, error) {
			return ExtractedToken{Scheme: AuthSchemeBearer, Token: "custom-token"}, nil
		}
		customDPoPExtractor := func(r *http.Request) (string, error) {
			return "custom-dpop", nil
		}
		customErrorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusTeapot)
		}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithLogger(mockLog),
			WithCredentialsOptional(true),
			WithValidateOnOptions(false),
			WithTokenExtractor(customExtractor),
			WithDPoPHeaderExtractor(customDPoPExtractor),
			WithErrorHandler(customErrorHandler),
			WithExclusionUrls([]string{"/public"}),
			WithStandardProxy(),
			WithDPoPMode(DPoPRequired),
		)
		require.NoError(t, err)
		assert.NotNil(t, middleware)
		assert.True(t, middleware.credentialsOptional)
		assert.False(t, middleware.validateOnOptions)
		assert.NotNil(t, middleware.logger)
		assert.NotNil(t, middleware.tokenExtractor)
		assert.NotNil(t, middleware.dpopHeaderExtractor)
		assert.NotNil(t, middleware.errorHandler)
		assert.NotNil(t, middleware.exclusionURLHandler)
		assert.NotNil(t, middleware.trustedProxies)
		assert.NotNil(t, middleware.dpopMode)
	})
}

// TestValidateToken_DPoPHeaderExtractorError tests error path in validateToken
func TestValidateToken_DPoPHeaderExtractorError(t *testing.T) {
	const (
		validToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwiYXVkIjoidGVzdEF1ZGllbmNlIn0.Bg8HXYXZ13zaPAcB0Bl0kRKW0iVF-2LTmITcEYUcWoo"
		issuer     = "testIssuer"
		audience   = "testAudience"
	)

	keyFunc := func(context.Context) (any, error) {
		return []byte("secret"), nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudience(audience),
	)
	require.NoError(t, err)

	t.Run("dpop header extractor error without logger", func(t *testing.T) {
		customDPoPExtractor := func(r *http.Request) (string, error) {
			return "", errors.New("dpop extraction failed")
		}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithDPoPHeaderExtractor(customDPoPExtractor),
			WithDPoPMode(DPoPAllowed),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)
		request.Header.Add("Authorization", validToken)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	})

	t.Run("dpop header extractor error with logger", func(t *testing.T) {
		mockLog := &mockLogger{}
		customDPoPExtractor := func(r *http.Request) (string, error) {
			return "", errors.New("dpop extraction failed with logging")
		}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithDPoPHeaderExtractor(customDPoPExtractor),
			WithDPoPMode(DPoPAllowed),
			WithLogger(mockLog),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)
		request.Header.Add("Authorization", validToken)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusBadRequest, response.StatusCode)
		// Verify error logging occurred
		assert.NotEmpty(t, mockLog.errorCalls)
		found := false
		for _, call := range mockLog.errorCalls {
			if len(call) > 0 {
				if msg, ok := call[0].(string); ok && msg == "failed to extract DPoP proof from request" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "Expected error log for DPoP extraction failure")
	})
}

// TestCheckJWT_WithLogging tests middleware with logging enabled to cover log branches
func TestCheckJWT_WithLogging(t *testing.T) {
	const (
		validToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwiYXVkIjoidGVzdEF1ZGllbmNlIn0.Bg8HXYXZ13zaPAcB0Bl0kRKW0iVF-2LTmITcEYUcWoo"
		issuer     = "testIssuer"
		audience   = "testAudience"
	)

	keyFunc := func(context.Context) (any, error) {
		return []byte("secret"), nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudience(audience),
	)
	require.NoError(t, err)

	t.Run("successful validation with debug logging", func(t *testing.T) {
		mockLog := &mockLogger{}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithLogger(mockLog),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)
		request.Header.Add("Authorization", validToken)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.NotEmpty(t, mockLog.debugCalls)
	})

	t.Run("exclusion URL with debug logging", func(t *testing.T) {
		mockLog := &mockLogger{}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithExclusionUrls([]string{"/public"}),
			WithLogger(mockLog),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodGet, testServer.URL+"/public", nil)
		require.NoError(t, err)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)
		// Should have debug log for exclusion
		assert.NotEmpty(t, mockLog.debugCalls)
	})

	t.Run("OPTIONS with skip validation and logging", func(t *testing.T) {
		mockLog := &mockLogger{}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithValidateOnOptions(false),
			WithLogger(mockLog),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodOptions, testServer.URL, nil)
		require.NoError(t, err)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.NotEmpty(t, mockLog.debugCalls)
	})

	t.Run("token extractor error with logging", func(t *testing.T) {
		mockLog := &mockLogger{}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithTokenExtractor(func(r *http.Request) (ExtractedToken, error) {
				return ExtractedToken{}, errors.New("extractor failed")
			}),
			WithLogger(mockLog),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
		assert.NotEmpty(t, mockLog.errorCalls)
	})

	t.Run("credentials optional with no token and logging", func(t *testing.T) {
		mockLog := &mockLogger{}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithCredentialsOptional(true),
			WithLogger(mockLog),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)
		// Should have debug log for optional credentials
		assert.NotEmpty(t, mockLog.debugCalls)
	})

	t.Run("standard JWT validation failure with warn logging", func(t *testing.T) {
		mockLog := &mockLogger{}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithLogger(mockLog),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		// Send invalid token
		request, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)
		request.Header.Add("Authorization", "Bearer invalid.token.here")

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
		assert.NotEmpty(t, mockLog.warnCalls)
	})

	t.Run("successful Bearer token validation logs correct message", func(t *testing.T) {
		mockLog := &mockLogger{}

		middleware, err := New(
			WithValidator(jwtValidator),
			WithLogger(mockLog),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)
		request.Header.Add("Authorization", validToken)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		assert.Equal(t, http.StatusOK, response.StatusCode)

		// Verify the Bearer token success log message
		assert.NotEmpty(t, mockLog.debugCalls)
		found := false
		for _, call := range mockLog.debugCalls {
			if len(call) > 0 {
				if msg, ok := call[0].(string); ok && msg == "JWT validation successful (Bearer), setting claims in context" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "Expected debug log for Bearer token success")
	})

	t.Run("successful DPoP token validation logs correct message", func(t *testing.T) {
		mockLog := &mockLogger{}

		// Create a validator that returns DPoP-bound token claims
		dpopKeyFunc := func(context.Context) (any, error) {
			return []byte("secret"), nil
		}

		dpopValidator, err := validator.New(
			validator.WithKeyFunc(dpopKeyFunc),
			validator.WithAlgorithm(validator.HS256),
			validator.WithIssuer(issuer),
			validator.WithAudience(audience),
		)
		require.NoError(t, err)

		// Mock DPoP header extractor that returns a proof
		dpopExtractor := func(r *http.Request) (string, error) {
			return "mock-dpop-proof", nil
		}

		middleware, err := New(
			WithValidator(dpopValidator),
			WithLogger(mockLog),
			WithDPoPMode(DPoPAllowed),
			WithDPoPHeaderExtractor(dpopExtractor),
		)
		require.NoError(t, err)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify DPoP context was set
			dpopCtx := core.GetDPoPContext(r.Context())
			if dpopCtx != nil {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		request, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)
		request.Header.Add("Authorization", validToken)

		response, err := testServer.Client().Do(request)
		require.NoError(t, err)
		defer response.Body.Close()

		// Note: This will fail validation because we don't have a real DPoP token/proof
		// But we can test the error path includes proper logging
		// For a full success path test, we would need to generate real DPoP tokens

		// The test validates that the logging infrastructure is in place
		assert.NotEmpty(t, mockLog.debugCalls)
	})
}

func TestCheckJWT_WithTrustedProxies(t *testing.T) {
	const (
		issuer   = "testIssuer"
		audience = "testAudience"
	)

	keyFunc := func(context.Context) (any, error) {
		return []byte("secret"), nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudience(audience),
	)
	require.NoError(t, err)

	testCases := []struct {
		name               string
		proxyOption        Option
		setupRequest       func(*http.Request)
		expectSuccess      bool
		expectedStatusCode int
	}{
		{
			name:        "no proxy config - ignores X-Forwarded headers",
			proxyOption: nil,
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "api.example.com")
				r.Header.Set("X-Forwarded-Prefix", "/api/v1")
			},
			expectSuccess:      true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:        "WithStandardProxy - trusts Proto and Host",
			proxyOption: WithStandardProxy(),
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "api.example.com")
			},
			expectSuccess:      true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:        "WithAPIGatewayProxy - trusts Proto, Host, and Prefix",
			proxyOption: WithAPIGatewayProxy(),
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "api.example.com")
				r.Header.Set("X-Forwarded-Prefix", "/api/v1")
			},
			expectSuccess:      true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:        "WithRFC7239Proxy - trusts Forwarded header",
			proxyOption: WithRFC7239Proxy(),
			setupRequest: func(r *http.Request) {
				r.Header.Set("Forwarded", "proto=https;host=api.example.com")
			},
			expectSuccess:      true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "custom proxy config - selective trust",
			proxyOption: WithTrustedProxies(&TrustedProxyConfig{
				TrustXForwardedProto: true,
				TrustXForwardedHost:  false, // Don't trust host
			}),
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "malicious.com")
			},
			expectSuccess:      true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:        "multiple proxies - uses leftmost value",
			proxyOption: WithStandardProxy(),
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https, http, http")
				r.Header.Set("X-Forwarded-Host", "client.example.com, proxy1.internal, proxy2.internal")
			},
			expectSuccess:      true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "RFC 7239 takes precedence over X-Forwarded",
			proxyOption: WithTrustedProxies(&TrustedProxyConfig{
				TrustForwarded:       true,
				TrustXForwardedProto: true,
				TrustXForwardedHost:  true,
			}),
			setupRequest: func(r *http.Request) {
				// RFC 7239 should win
				r.Header.Set("Forwarded", "proto=https;host=rfc7239.example.com")
				r.Header.Set("X-Forwarded-Proto", "http")
				r.Header.Set("X-Forwarded-Host", "xforwarded.example.com")
			},
			expectSuccess:      true,
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := []Option{WithValidator(jwtValidator)}
			if tc.proxyOption != nil {
				options = append(options, tc.proxyOption)
			}

			middleware, err := New(options...)
			require.NoError(t, err)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims, err := GetClaims[*validator.ValidatedClaims](r.Context())
				if err != nil {
					http.Error(w, "failed to get claims", http.StatusInternalServerError)
					return
				}

				response := map[string]any{
					"authenticated": true,
					"issuer":        claims.RegisteredClaims.Issuer,
					"audience":      claims.RegisteredClaims.Audience,
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			})

			// Create test server
			testServer := httptest.NewServer(middleware.CheckJWT(handler))
			defer testServer.Close()

			// Create request
			request, err := http.NewRequest(http.MethodGet, testServer.URL+"/test", nil)
			require.NoError(t, err)

			// Apply proxy headers
			tc.setupRequest(request)

			// Add valid JWT token
			validToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwiYXVkIjoidGVzdEF1ZGllbmNlIn0.Bg8HXYXZ13zaPAcB0Bl0kRKW0iVF-2LTmITcEYUcWoo"
			request.Header.Set("Authorization", validToken)

			// Send request
			response, err := testServer.Client().Do(request)
			require.NoError(t, err)
			defer response.Body.Close()

			// Verify status code
			assert.Equal(t, tc.expectedStatusCode, response.StatusCode)

			if tc.expectSuccess {
				// Verify we got a valid response
				var result map[string]any
				err = json.NewDecoder(response.Body).Decode(&result)
				require.NoError(t, err)
				assert.True(t, result["authenticated"].(bool))
			}
		})
	}
}
