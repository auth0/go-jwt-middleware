package jwtmiddleware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v2/validator"
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

	keyFunc := func(context.Context) (interface{}, error) {
		return []byte("secret"), nil
	}

	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc), validator.WithSignatureAlgorithm(validator.HS256), validator.WithIssuer(issuer), validator.WithAudience(audience))
	require.NoError(t, err)

	testCases := []struct {
		name           string
		validateToken  ValidateToken
		options        []Option
		method         string
		token          string
		wantToken      interface{}
		wantStatusCode int
		wantBody       string
		path           string
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
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"message":"JWT is invalid","detail":"error extracting token: authorization header format must be 'Bearer {token}'"}`,
		},
		{
			name:           "it fails to validate if token is missing and credentials are not optional",
			token:          "",
			method:         http.MethodGet,
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing"}`,
		},
		{
			name:           "it fails to validate an invalid token",
			validateToken:  jwtValidator.ValidateToken,
			token:          invalidToken,
			method:         http.MethodGet,
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"message":"JWT is invalid","detail":"token validation failed: could not verify message using any of the signatures or keys"}`,
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
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", errors.New("token extractor error")
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusUnauthorized,
			wantBody:       `{"message":"JWT is invalid","detail":"error extracting token: token extractor error"}`,
		},
		{
			name: "it calls the custom error handler when token validation fails",
			options: []Option{
				WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write(fmt.Appendf(nil, `{"message":"Custom error: %s"}`, err.Error()))
				}),
			},
			validateToken: func(context.Context, string) (interface{}, error) {
				return nil, errors.New("token validation failed")
			},
			token:          "invalid_token",
			method:         http.MethodGet,
			wantStatusCode: http.StatusForbidden,
			wantBody:       `{"message":"Custom error: JWT is invalid: error extracting token: authorization header format must be 'Bearer {token}'"}`,
		},
		{
			name: "credentialsOptional true",
			options: []Option{
				WithCredentialsOptional(true),
				WithTokenExtractor(func(r *http.Request) (string, error) {
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
			options: []Option{
				WithCredentialsOptional(false),
				WithTokenExtractor(func(r *http.Request) (string, error) {
					return "", nil
				}),
			},
			method:         http.MethodGet,
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing"}`,
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
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing"}`,
		},
		{
			name: "JWT not required for /custom_exclusion using WithExclusionUrlHandler",
			options: []Option{
				WithExclusionUrlHandler(func(r *http.Request) bool {
					return r.URL.Path == "/custom_exclusion"
				}),
			},
			method:         http.MethodGet,
			path:           "/custom_exclusion",
			token:          "",
			wantStatusCode: http.StatusOK,
			wantBody:       `{"message":"Authenticated."}`,
		},
		{
			name: "JWT required for /not_excluded using WithExclusionUrlHandler",
			options: []Option{
				WithExclusionUrlHandler(func(r *http.Request) bool {
					return r.URL.Path == "/custom_exclusion"
				}),
			},
			method:         http.MethodGet,
			path:           "/not_excluded",
			token:          "",
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"message":"JWT is missing"}`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			middleware := New(testCase.validateToken, testCase.options...)

			var actualValidatedClaims interface{}
			var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actualValidatedClaims = r.Context().Value(DefaultClaimsKey)
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
			assert.Equal(t, testCase.wantBody, string(body))

			if want, got := testCase.wantToken, actualValidatedClaims; !cmp.Equal(want, got) {
				t.Fatal(cmp.Diff(want, got))
			}
		})
	}
}

// Tests for accessor methods
func TestMiddlewareAccessors(t *testing.T) {
	customLogger := &testLogger{}
	customTracer := &testTracer{}
	customMetrics := &testMetrics{}

	t.Run("Logger returns the configured logger", func(t *testing.T) {
		m := &JWTMiddleware{logger: customLogger}
		assert.Equal(t, customLogger, m.Logger())

		// Test with nil logger
		m = &JWTMiddleware{logger: nil}
		assert.Nil(t, m.Logger())
	})

	t.Run("LogLevel returns the configured log level", func(t *testing.T) {
		m := &JWTMiddleware{logLevel: LogLevelDebug}
		assert.Equal(t, LogLevelDebug, m.LogLevel())

		m = &JWTMiddleware{logLevel: LogLevelError}
		assert.Equal(t, LogLevelError, m.LogLevel())
	})

	t.Run("GetContextKey returns the configured context key or default", func(t *testing.T) {
		// Test with custom key
		customKey := ContextKey{Name: "custom-key"}
		m := &JWTMiddleware{contextKey: customKey}
		assert.Equal(t, customKey, m.GetContextKey())

		// Test with empty key (should return default)
		m = &JWTMiddleware{contextKey: ContextKey{}}
		assert.Equal(t, DefaultClaimsKey, m.GetContextKey())
	})

	t.Run("Tracer returns the configured tracer or NoopTracer", func(t *testing.T) {
		// Test with custom tracer
		m := &JWTMiddleware{tracer: customTracer}
		assert.Equal(t, customTracer, m.Tracer())

		// Test with nil tracer (should return NoopTracer)
		m = &JWTMiddleware{tracer: nil}
		_, isNoopTracer := m.Tracer().(*NoopTracer)
		assert.True(t, isNoopTracer)
	})

	t.Run("Metrics returns the configured metrics or NoopMetrics", func(t *testing.T) {
		// Test with custom metrics
		m := &JWTMiddleware{metrics: customMetrics}
		assert.Equal(t, customMetrics, m.Metrics())

		// Test with nil metrics (should return NoopMetrics)
		m = &JWTMiddleware{metrics: nil}
		_, isNoopMetrics := m.Metrics().(*NoopMetrics)
		assert.True(t, isNoopMetrics)
	})
}

// Tests for the GetClaims functions
func TestGetClaimsFunctions(t *testing.T) {
	// Create sample claims
	claims := &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{
			Subject: "test-subject",
		},
	}

	t.Run("GetClaims retrieves claims with default key", func(t *testing.T) {
		// Create context with claims using default key
		ctx := context.WithValue(context.Background(), DefaultClaimsKey, claims)

		// Get claims
		retrievedClaims, err := GetClaims(ctx)
		assert.NoError(t, err)
		assert.Equal(t, claims, retrievedClaims)
	})

	t.Run("GetClaims returns error when claims are missing", func(t *testing.T) {
		// Create empty context
		ctx := context.Background()

		// Try to get claims
		retrievedClaims, err := GetClaims(ctx)
		assert.Error(t, err)
		assert.Equal(t, ErrMissingClaims, err)
		assert.Nil(t, retrievedClaims)
	})

	t.Run("GetClaimsWithKey retrieves claims with custom key", func(t *testing.T) {
		customKey := "custom-key"
		// Create context with claims using custom key
		ctx := context.WithValue(context.Background(), ContextKey{Name: customKey}, claims)

		// Get claims with custom key
		retrievedClaims, err := GetClaimsWithKey(ctx, customKey)
		assert.NoError(t, err)
		assert.Equal(t, claims, retrievedClaims)
	})

	t.Run("GetClaimsWithKey uses default key when empty key is provided", func(t *testing.T) {
		// Create context with claims using default key
		ctx := context.WithValue(context.Background(), DefaultClaimsKey, claims)

		// Get claims with empty key (should use default)
		retrievedClaims, err := GetClaimsWithKey(ctx, "")
		assert.NoError(t, err)
		assert.Equal(t, claims, retrievedClaims)
	})

	t.Run("GetClaimsWithKey returns error for invalid claim type", func(t *testing.T) {
		invalidClaims := "not a ValidatedClaims object"
		ctx := context.WithValue(context.Background(), ContextKey{Name: "key"}, invalidClaims)

		retrievedClaims, err := GetClaimsWithKey(ctx, "key")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidClaims, err)
		assert.Nil(t, retrievedClaims)
	})
}

// Tests for each middleware option
func TestMiddlewareOptions(t *testing.T) {
	t.Run("WithCredentialsOptional", func(t *testing.T) {
		// Test with true
		m := &JWTMiddleware{}
		WithCredentialsOptional(true)(m)
		assert.True(t, m.credentialsOptional, "credentialsOptional should be true")

		// Test with false
		m = &JWTMiddleware{}
		WithCredentialsOptional(false)(m)
		assert.False(t, m.credentialsOptional, "credentialsOptional should be false")
	})

	t.Run("WithValidateOnOptions", func(t *testing.T) {
		// Test with true
		m := &JWTMiddleware{}
		WithValidateOnOptions(true)(m)
		assert.True(t, m.validateOnOptions, "validateOnOptions should be true")

		// Test with false
		m = &JWTMiddleware{}
		WithValidateOnOptions(false)(m)
		assert.False(t, m.validateOnOptions, "validateOnOptions should be false")
	})

	t.Run("WithErrorHandler", func(t *testing.T) {
		m := &JWTMiddleware{}
		customHandler := func(w http.ResponseWriter, r *http.Request, err error) {
			// Custom handler logic
		}
		WithErrorHandler(customHandler)(m)

		// Check if the handler was correctly set
		assert.NotNil(t, m.errorHandler, "errorHandler should not be nil")
	})

	t.Run("WithTokenExtractor", func(t *testing.T) {
		m := &JWTMiddleware{}
		customExtractor := func(r *http.Request) (string, error) {
			return "custom-token", nil
		}
		WithTokenExtractor(customExtractor)(m)

		// Check if the extractor was correctly set
		assert.NotNil(t, m.tokenExtractor, "tokenExtractor should not be nil")

		// Test the extractor
		token, err := m.tokenExtractor(&http.Request{})
		assert.NoError(t, err, "tokenExtractor should not return an error")
		assert.Equal(t, "custom-token", token, "tokenExtractor should return the expected token")
	})

	t.Run("WithExclusionUrls", func(t *testing.T) {
		m := &JWTMiddleware{}
		urls := []string{"/public", "/health"}
		WithExclusionUrls(urls)(m)

		// Check if the handler was correctly set
		assert.NotNil(t, m.exclusionUrlHandler, "exclusionUrlHandler should not be nil")

		// Test the handler with matching URL
		req, _ := http.NewRequest("GET", "http://example.com/public", nil)
		assert.True(t, m.exclusionUrlHandler(req), "URL should be excluded")

		// Test the handler with non-matching URL
		req, _ = http.NewRequest("GET", "http://example.com/private", nil)
		assert.False(t, m.exclusionUrlHandler(req), "URL should not be excluded")

		// Test with path matching
		req, _ = http.NewRequest("GET", "http://example.com/health?param=value", nil)
		assert.True(t, m.exclusionUrlHandler(req), "Path should be excluded")
	})

	t.Run("WithExclusionUrlHandler", func(t *testing.T) {
		m := &JWTMiddleware{}
		customHandler := func(r *http.Request) bool {
			return r.URL.Path == "/custom"
		}
		WithExclusionUrlHandler(customHandler)(m)

		// Check if the handler was correctly set
		assert.NotNil(t, m.exclusionUrlHandler, "exclusionUrlHandler should not be nil")

		// Test the handler functionality
		req, _ := http.NewRequest("GET", "http://example.com/custom", nil)
		assert.True(t, m.exclusionUrlHandler(req), "URL should be excluded")

		req, _ = http.NewRequest("GET", "http://example.com/other", nil)
		assert.False(t, m.exclusionUrlHandler(req), "URL should not be excluded")
	})

	t.Run("WithContextKey", func(t *testing.T) {
		m := &JWTMiddleware{}
		WithContextKey("custom-key")(m)

		// Check if the context key was correctly set
		assert.Equal(t, "custom-key", m.contextKey.Name, "contextKey should be set to the custom key")
	})

	t.Run("WithLogger", func(t *testing.T) {
		// Test with custom logger
		m := &JWTMiddleware{}
		customLogger := &testLogger{}
		WithLogger(customLogger, LogLevelDebug)(m)

		assert.Equal(t, customLogger, m.logger, "logger should be set to the custom logger")
		assert.Equal(t, LogLevelDebug, m.logLevel, "logLevel should be set to Debug")

		// Test with nil logger (should use default)
		m = &JWTMiddleware{}
		WithLogger(nil, LogLevelError)(m)

		_, isDefaultLogger := m.logger.(*DefaultLogger)
		assert.True(t, isDefaultLogger, "logger should be set to DefaultLogger when nil is provided")
		assert.Equal(t, LogLevelError, m.logLevel, "logLevel should be set to Error")

		// Test with LogLevelNone (should use LogLevelInfo)
		m = &JWTMiddleware{}
		WithLogger(customLogger, LogLevelNone)(m)

		assert.Equal(t, customLogger, m.logger, "logger should be set to the custom logger")
		assert.Equal(t, LogLevelInfo, m.logLevel, "logLevel should be set to Info when LogLevelNone is provided")
	})

	t.Run("WithTracer", func(t *testing.T) {
		// Test with custom tracer
		m := &JWTMiddleware{}
		customTracer := &testTracer{}
		WithTracer(customTracer)(m)

		assert.Equal(t, customTracer, m.tracer, "tracer should be set to the custom tracer")

		// Test with nil tracer (should use NoopTracer)
		m = &JWTMiddleware{}
		WithTracer(nil)(m)

		_, isNoopTracer := m.tracer.(*NoopTracer)
		assert.True(t, isNoopTracer, "tracer should be set to NoopTracer when nil is provided")
	})

	t.Run("WithMetrics", func(t *testing.T) {
		// Test with custom metrics
		m := &JWTMiddleware{}
		customMetrics := &testMetrics{}
		WithMetrics(customMetrics)(m)

		assert.Equal(t, customMetrics, m.metrics, "metrics should be set to the custom metrics")

		// Test with nil metrics (should use NoopMetrics)
		m = &JWTMiddleware{}
		WithMetrics(nil)(m)

		_, isNoopMetrics := m.metrics.(*NoopMetrics)
		assert.True(t, isNoopMetrics, "metrics should be set to NoopMetrics when nil is provided")
	})
}

// Mock implementations for testing
// These may already exist elsewhere in test files, if not they're defined here

type testLogger struct{}

func (l *testLogger) Debugf(format string, args ...interface{}) {}
func (l *testLogger) Infof(format string, args ...interface{})  {}
func (l *testLogger) Warnf(format string, args ...interface{})  {}
func (l *testLogger) Errorf(format string, args ...interface{}) {}

type testTracer struct{}

func (t *testTracer) StartSpan(name string, args ...interface{}) Span {
	return &testSpan{}
}

type testSpan struct{}

func (s *testSpan) Finish()                         {}
func (s *testSpan) SetTag(key string, value any)    {}
func (s *testSpan) LogFields(fields ...interface{}) {}

type testMetrics struct{}

func (m *testMetrics) IncCounter(name string, tags map[string]string)                      {}
func (m *testMetrics) ObserveHistogram(name string, value float64, tags map[string]string) {}
func (m *testMetrics) SetGauge(name string, value float64, tags map[string]string)         {}
