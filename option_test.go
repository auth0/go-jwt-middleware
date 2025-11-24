package jwtmiddleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_New_OptionsValidation(t *testing.T) {
	validValidator := func(ctx context.Context, token string) (any, error) {
		return map[string]any{"sub": "user-123"}, nil
	}

	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
		errMsg  string
	}{
		{
			name:    "missing validator",
			opts:    []Option{},
			wantErr: true,
			errMsg:  "validateToken cannot be nil",
		},
		{
			name: "nil validator",
			opts: []Option{
				WithValidateToken(nil),
			},
			wantErr: true,
			errMsg:  "validateToken cannot be nil",
		},
		{
			name: "valid minimal configuration",
			opts: []Option{
				WithValidateToken(validValidator),
			},
			wantErr: false,
		},
		{
			name: "nil error handler",
			opts: []Option{
				WithValidateToken(validValidator),
				WithErrorHandler(nil),
			},
			wantErr: true,
			errMsg:  "errorHandler cannot be nil",
		},
		{
			name: "nil token extractor",
			opts: []Option{
				WithValidateToken(validValidator),
				WithTokenExtractor(nil),
			},
			wantErr: true,
			errMsg:  "tokenExtractor cannot be nil",
		},
		{
			name: "empty exclusion URLs",
			opts: []Option{
				WithValidateToken(validValidator),
				WithExclusionUrls([]string{}),
			},
			wantErr: true,
			errMsg:  "exclusion URLs list cannot be empty",
		},
		{
			name: "valid exclusion URLs",
			opts: []Option{
				WithValidateToken(validValidator),
				WithExclusionUrls([]string{"/health", "/metrics"}),
			},
			wantErr: false,
		},
		{
			name: "nil logger",
			opts: []Option{
				WithValidateToken(validValidator),
				WithLogger(nil),
			},
			wantErr: true,
			errMsg:  "logger cannot be nil",
		},
		{
			name: "valid logger",
			opts: []Option{
				WithValidateToken(validValidator),
				WithLogger(&mockLogger{}),
			},
			wantErr: false,
		},
		{
			name: "valid configuration with all options",
			opts: []Option{
				WithValidateToken(validValidator),
				WithCredentialsOptional(true),
				WithValidateOnOptions(false),
				WithErrorHandler(DefaultErrorHandler),
				WithTokenExtractor(AuthHeaderTokenExtractor),
				WithExclusionUrls([]string{"/public"}),
				WithLogger(&mockLogger{}),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := New(tt.opts...)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, middleware)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, middleware)
				assert.NotNil(t, middleware.validateToken)
				assert.NotNil(t, middleware.errorHandler)
				assert.NotNil(t, middleware.tokenExtractor)
			}
		})
	}
}

func Test_New_Defaults(t *testing.T) {
	validValidator := func(ctx context.Context, token string) (any, error) {
		return map[string]any{"sub": "user-123"}, nil
	}

	middleware, err := New(
		WithValidateToken(validValidator),
	)
	require.NoError(t, err)

	// Check defaults
	assert.NotNil(t, middleware.errorHandler)
	assert.NotNil(t, middleware.tokenExtractor)
	assert.False(t, middleware.credentialsOptional)
	assert.True(t, middleware.validateOnOptions)
	assert.Nil(t, middleware.exclusionURLHandler)
}

func Test_WithCredentialsOptional(t *testing.T) {
	validValidator := func(ctx context.Context, token string) (any, error) {
		return map[string]any{"sub": "user-123"}, nil
	}

	tests := []struct {
		name  string
		value bool
	}{
		{
			name:  "credentials optional true",
			value: true,
		},
		{
			name:  "credentials optional false",
			value: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := New(
				WithValidateToken(validValidator),
				WithCredentialsOptional(tt.value),
			)
			require.NoError(t, err)
			assert.Equal(t, tt.value, middleware.credentialsOptional)
		})
	}
}

func Test_WithValidateOnOptions(t *testing.T) {
	validValidator := func(ctx context.Context, token string) (any, error) {
		return map[string]any{"sub": "user-123"}, nil
	}

	tests := []struct {
		name  string
		value bool
	}{
		{
			name:  "validate on OPTIONS true",
			value: true,
		},
		{
			name:  "validate on OPTIONS false",
			value: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := New(
				WithValidateToken(validValidator),
				WithValidateOnOptions(tt.value),
			)
			require.NoError(t, err)
			assert.Equal(t, tt.value, middleware.validateOnOptions)
		})
	}
}

func Test_WithErrorHandler(t *testing.T) {
	validValidator := func(ctx context.Context, token string) (any, error) {
		return map[string]any{"sub": "user-123"}, nil
	}

	customHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusTeapot)
	}

	middleware, err := New(
		WithValidateToken(validValidator),
		WithErrorHandler(customHandler),
	)
	require.NoError(t, err)
	assert.NotNil(t, middleware.errorHandler)
}

func Test_WithTokenExtractor(t *testing.T) {
	validValidator := func(ctx context.Context, token string) (any, error) {
		return map[string]any{"sub": "user-123"}, nil
	}

	customExtractor := func(r *http.Request) (string, error) {
		return "custom-token", nil
	}

	middleware, err := New(
		WithValidateToken(validValidator),
		WithTokenExtractor(customExtractor),
	)
	require.NoError(t, err)
	assert.NotNil(t, middleware.tokenExtractor)
}

func Test_WithExclusionUrls(t *testing.T) {
	validValidator := func(ctx context.Context, token string) (any, error) {
		return map[string]any{"sub": "user-123"}, nil
	}

	exclusions := []string{"/health", "/metrics", "/public"}

	middleware, err := New(
		WithValidateToken(validValidator),
		WithExclusionUrls(exclusions),
	)
	require.NoError(t, err)
	assert.NotNil(t, middleware.exclusionURLHandler)

	// Test the exclusion handler
	testCases := []struct {
		name     string
		path     string
		excluded bool
	}{
		{"health endpoint", "/health", true},
		{"metrics endpoint", "/metrics", true},
		{"public endpoint", "/public", true},
		{"secure endpoint", "/secure", false},
		{"api endpoint", "/api/users", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://example.com"+tc.path, nil)
			require.NoError(t, err)

			result := middleware.exclusionURLHandler(req)
			assert.Equal(t, tc.excluded, result)
		})
	}
}

func Test_WithLogger(t *testing.T) {
	t.Run("credentials optional with no token and logging", func(t *testing.T) {
		logger := &mockLogger{}
		validator := func(ctx context.Context, token string) (any, error) {
			return map[string]any{"sub": "user-123"}, nil
		}

		middleware, err := New(
			WithValidateToken(validator),
			WithLogger(logger),
			WithCredentialsOptional(true),
			WithTokenExtractor(func(r *http.Request) (string, error) {
				return "", nil // No token
			}),
		)
		require.NoError(t, err)

		// Create a test server with the middleware
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		// Make a request without token but credentials optional
		req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)

		resp, err := testServer.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify logging occurred for optional credentials
		assert.Greater(t, len(logger.debugCalls), 0, "expected debug logs")
		// Should have log about continuing without claims
		foundOptionalLog := false
		for _, call := range logger.debugCalls {
			if len(call) > 0 {
				if msg, ok := call[0].(string); ok && msg == "no credentials provided, continuing without claims (credentials optional)" {
					foundOptionalLog = true
					break
				}
			}
		}
		assert.True(t, foundOptionalLog, "expected log about continuing without claims")
	})

	t.Run("successful validation with logging", func(t *testing.T) {
		logger := &mockLogger{}
		validator := func(ctx context.Context, token string) (any, error) {
			return map[string]any{"sub": "user-123"}, nil
		}

		middleware, err := New(
			WithValidateToken(validator),
			WithLogger(logger),
		)
		require.NoError(t, err)
		assert.NotNil(t, middleware.logger)

		// Create a test server with the middleware
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		// Make a request with a valid token
		req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer test-token")

		resp, err := testServer.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify logging occurred
		assert.Greater(t, len(logger.debugCalls), 0, "expected debug logs")
		// Should have logs for: extracting JWT, validating JWT, validation successful
		assert.GreaterOrEqual(t, len(logger.debugCalls), 3)
	})

	t.Run("validation failure with logging", func(t *testing.T) {
		logger := &mockLogger{}
		validator := func(ctx context.Context, token string) (any, error) {
			return nil, errors.New("invalid token")
		}

		middleware, err := New(
			WithValidateToken(validator),
			WithLogger(logger),
		)
		require.NoError(t, err)

		// Create a test server with the middleware
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		// Make a request with an invalid token
		req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer bad-token")

		resp, err := testServer.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify logging occurred
		assert.Greater(t, len(logger.debugCalls), 0, "expected debug logs")
		assert.Greater(t, len(logger.warnCalls), 0, "expected warn logs for validation failure")
	})

	t.Run("excluded URL with logging", func(t *testing.T) {
		logger := &mockLogger{}
		validator := func(ctx context.Context, token string) (any, error) {
			return map[string]any{"sub": "user-123"}, nil
		}

		middleware, err := New(
			WithValidateToken(validator),
			WithLogger(logger),
			WithExclusionUrls([]string{"/health"}),
		)
		require.NoError(t, err)

		// Create a test server with the middleware
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		// Make a request to excluded URL without token
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/health", nil)
		require.NoError(t, err)

		resp, err := testServer.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify logging occurred for excluded URL
		assert.Greater(t, len(logger.debugCalls), 0, "expected debug logs")
		// Should have log about skipping validation
		foundSkipLog := false
		for _, call := range logger.debugCalls {
			if len(call) > 0 {
				if msg, ok := call[0].(string); ok && msg == "skipping JWT validation for excluded URL" {
					foundSkipLog = true
					break
				}
			}
		}
		assert.True(t, foundSkipLog, "expected log about skipping validation for excluded URL")
	})

	t.Run("OPTIONS request with logging", func(t *testing.T) {
		logger := &mockLogger{}
		validator := func(ctx context.Context, token string) (any, error) {
			return map[string]any{"sub": "user-123"}, nil
		}

		middleware, err := New(
			WithValidateToken(validator),
			WithLogger(logger),
			WithValidateOnOptions(false),
		)
		require.NoError(t, err)

		// Create a test server with the middleware
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		// Make an OPTIONS request without token
		req, err := http.NewRequest(http.MethodOptions, testServer.URL, nil)
		require.NoError(t, err)

		resp, err := testServer.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify logging occurred for OPTIONS request
		assert.Greater(t, len(logger.debugCalls), 0, "expected debug logs")
		// Should have log about skipping validation for OPTIONS
		foundSkipLog := false
		for _, call := range logger.debugCalls {
			if len(call) > 0 {
				if msg, ok := call[0].(string); ok && msg == "skipping JWT validation for OPTIONS request" {
					foundSkipLog = true
					break
				}
			}
		}
		assert.True(t, foundSkipLog, "expected log about skipping validation for OPTIONS request")
	})

	t.Run("token extraction error with logging", func(t *testing.T) {
		logger := &mockLogger{}
		validator := func(ctx context.Context, token string) (any, error) {
			return map[string]any{"sub": "user-123"}, nil
		}

		customExtractor := func(r *http.Request) (string, error) {
			return "", errors.New("extraction failed")
		}

		middleware, err := New(
			WithValidateToken(validator),
			WithLogger(logger),
			WithTokenExtractor(customExtractor),
		)
		require.NoError(t, err)

		// Create a test server with the middleware
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})

		testServer := httptest.NewServer(middleware.CheckJWT(handler))
		defer testServer.Close()

		// Make a request
		req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
		require.NoError(t, err)

		resp, err := testServer.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify error logging occurred
		assert.Greater(t, len(logger.errorCalls), 0, "expected error logs for extraction failure")
	})
}

func Test_GetClaims(t *testing.T) {
	type CustomClaims struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}

	// Helper to create context with claims using the middleware's internal method
	// We test through the actual middleware flow
	createContextWithClaims := func(claims any) context.Context {
		// Create a test request that goes through the middleware
		validator := func(ctx context.Context, token string) (any, error) {
			return claims, nil
		}

		middleware, _ := New(WithValidateToken(validator))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		var resultCtx context.Context
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resultCtx = r.Context()
		})

		rr := httptest.NewRecorder()
		middleware.CheckJWT(handler).ServeHTTP(rr, req)

		return resultCtx
	}

	tests := []struct {
		name      string
		setupCtx  func() context.Context
		wantClaim *CustomClaims
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid claims",
			setupCtx: func() context.Context {
				claims := &CustomClaims{UserID: "user-123", Role: "admin"}
				return createContextWithClaims(claims)
			},
			wantClaim: &CustomClaims{UserID: "user-123", Role: "admin"},
			wantErr:   false,
		},
		{
			name: "claims not found",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantErr: true,
			errMsg:  "claims not found in context",
		},
		{
			name: "claims wrong type",
			setupCtx: func() context.Context {
				wrongClaims := map[string]any{"sub": "user-123"}
				return createContextWithClaims(wrongClaims)
			},
			wantErr: true,
			errMsg:  "claims have wrong type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			claims, err := GetClaims[*CustomClaims](ctx)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantClaim, claims)
			}
		})
	}
}

func Test_MustGetClaims(t *testing.T) {
	type CustomClaims struct {
		UserID string `json:"user_id"`
	}

	// Helper to create context with claims through middleware
	createContextWithClaims := func(claims any) context.Context {
		validator := func(ctx context.Context, token string) (any, error) {
			return claims, nil
		}

		middleware, _ := New(WithValidateToken(validator))
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		var resultCtx context.Context
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resultCtx = r.Context()
		})

		rr := httptest.NewRecorder()
		middleware.CheckJWT(handler).ServeHTTP(rr, req)
		return resultCtx
	}

	t.Run("valid claims", func(t *testing.T) {
		claims := &CustomClaims{UserID: "user-123"}
		ctx := createContextWithClaims(claims)

		result := MustGetClaims[*CustomClaims](ctx)
		assert.Equal(t, claims, result)
	})

	t.Run("panics on missing claims", func(t *testing.T) {
		ctx := context.Background()

		assert.Panics(t, func() {
			MustGetClaims[*CustomClaims](ctx)
		})
	})

	t.Run("panics on wrong type", func(t *testing.T) {
		wrongClaims := map[string]any{"sub": "user-123"}
		ctx := createContextWithClaims(wrongClaims)

		assert.Panics(t, func() {
			MustGetClaims[*CustomClaims](ctx)
		})
	})
}

func Test_HasClaims(t *testing.T) {
	// Helper to create context with claims through middleware
	createContextWithClaims := func() context.Context {
		validator := func(ctx context.Context, token string) (any, error) {
			return map[string]any{"sub": "user-123"}, nil
		}

		middleware, _ := New(WithValidateToken(validator))
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		var resultCtx context.Context
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resultCtx = r.Context()
		})

		rr := httptest.NewRecorder()
		middleware.CheckJWT(handler).ServeHTTP(rr, req)
		return resultCtx
	}

	tests := []struct {
		name     string
		setupCtx func() context.Context
		want     bool
	}{
		{
			name: "has claims",
			setupCtx: func() context.Context {
				return createContextWithClaims()
			},
			want: true,
		},
		{
			name: "no claims",
			setupCtx: func() context.Context {
				return context.Background()
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			result := HasClaims(ctx)
			assert.Equal(t, tt.want, result)
		})
	}
}

func Test_SentinelErrors(t *testing.T) {
	t.Run("ErrValidateTokenNil", func(t *testing.T) {
		assert.True(t, errors.Is(ErrValidateTokenNil, ErrValidateTokenNil))
		assert.Contains(t, ErrValidateTokenNil.Error(), "validateToken cannot be nil")
	})

	t.Run("ErrErrorHandlerNil", func(t *testing.T) {
		assert.True(t, errors.Is(ErrErrorHandlerNil, ErrErrorHandlerNil))
		assert.Contains(t, ErrErrorHandlerNil.Error(), "errorHandler cannot be nil")
	})

	t.Run("ErrTokenExtractorNil", func(t *testing.T) {
		assert.True(t, errors.Is(ErrTokenExtractorNil, ErrTokenExtractorNil))
		assert.Contains(t, ErrTokenExtractorNil.Error(), "tokenExtractor cannot be nil")
	})

	t.Run("ErrExclusionUrlsEmpty", func(t *testing.T) {
		assert.True(t, errors.Is(ErrExclusionUrlsEmpty, ErrExclusionUrlsEmpty))
		assert.Contains(t, ErrExclusionUrlsEmpty.Error(), "exclusion URLs list cannot be empty")
	})
}

func Test_validatorAdapter(t *testing.T) {
	validateFunc := func(ctx context.Context, token string) (any, error) {
		return map[string]any{"sub": "test"}, nil
	}

	adapter := &validatorAdapter{validateFunc: validateFunc}

	t.Run("successful validation", func(t *testing.T) {
		result, err := adapter.ValidateToken(context.Background(), "test-token")
		require.NoError(t, err)
		assert.NotNil(t, result)
		claims, ok := result.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "test", claims["sub"])
	})

	t.Run("validation error", func(t *testing.T) {
		errAdapter := &validatorAdapter{
			validateFunc: func(ctx context.Context, token string) (any, error) {
				return nil, errors.New("validation failed")
			},
		}
		result, err := errAdapter.ValidateToken(context.Background(), "bad-token")
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func Test_invalidError(t *testing.T) {
	t.Run("Error method returns formatted message", func(t *testing.T) {
		detailErr := errors.New("token signature is invalid")
		invErr := &invalidError{details: detailErr}

		errMsg := invErr.Error()
		assert.Contains(t, errMsg, "jwt invalid")
		assert.Contains(t, errMsg, "token signature is invalid")
	})

	t.Run("Is method works with ErrJWTInvalid", func(t *testing.T) {
		detailErr := errors.New("some validation error")
		invErr := &invalidError{details: detailErr}

		assert.True(t, errors.Is(invErr, ErrJWTInvalid))
	})

	t.Run("Unwrap returns the details error", func(t *testing.T) {
		detailErr := errors.New("specific error details")
		invErr := &invalidError{details: detailErr}

		assert.Equal(t, detailErr, errors.Unwrap(invErr))
	})
}

// mockLogger is a test implementation of the Logger interface
type mockLogger struct {
	debugCalls [][]any
	infoCalls  [][]any
	warnCalls  [][]any
	errorCalls [][]any
}

func (m *mockLogger) Debug(msg string, args ...any) {
	m.debugCalls = append(m.debugCalls, append([]any{msg}, args...))
}

func (m *mockLogger) Info(msg string, args ...any) {
	m.infoCalls = append(m.infoCalls, append([]any{msg}, args...))
}

func (m *mockLogger) Warn(msg string, args ...any) {
	m.warnCalls = append(m.warnCalls, append([]any{msg}, args...))
}

func (m *mockLogger) Error(msg string, args ...any) {
	m.errorCalls = append(m.errorCalls, append([]any{msg}, args...))
}
