package grpcjwt

import (
	"context"
	"errors"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"testing"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Mock token validator function
// Mock token validator function
func mockValidateToken(validToken string) jwtmiddleware.ValidateToken {
	return func(ctx context.Context, token string) (interface{}, error) {
		if token != validToken {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		return &validator.ValidatedClaims{
			RegisteredClaims: validator.RegisteredClaims{
				Subject: "user123",
			},
		}, nil
	}
}

func TestUnaryInterceptor(t *testing.T) {
	validToken := "validToken123"
	invalidToken := "invalidToken456"

	tests := []struct {
		name           string
		token          string
		options        []Option
		method         string
		expectErr      bool
		expectedCode   codes.Code
		expectedClaims bool
	}{
		{
			name:           "valid token",
			token:          validToken,
			expectErr:      false,
			expectedClaims: true,
		},
		{
			name:         "invalid token",
			token:        invalidToken,
			expectErr:    true,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "missing token",
			token:        "",
			expectErr:    true,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:  "optional credentials with missing token",
			token: "",
			options: []Option{
				WithCredentialsOptional(true),
			},
			expectErr:      false,
			expectedClaims: false,
		},
		{
			name:   "excluded method",
			token:  "",
			method: "/test.service/ExcludedMethod",
			options: []Option{
				WithExclusionMethods([]string{"/test.service/ExcludedMethod"}),
			},
			expectErr:      false,
			expectedClaims: false,
		},
		{
			name:  "WithTokenExtractor",
			token: validToken,
			options: []Option{
				WithTokenExtractor(func(ctx context.Context) (string, error) {
					return validToken, nil
				}),
			},
			expectErr:      false,
			expectedClaims: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create interceptor with fixed mockValidateToken
			interceptor := New(mockValidateToken(validToken), tt.options...)
			unaryInterceptor := interceptor.UnaryServerInterceptor()

			// Create context with or without token
			ctx := context.Background()
			if tt.token != "" {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+tt.token))
			}

			// Define method info
			methodName := "/test.service/TestMethod"
			if tt.method != "" {
				methodName = tt.method
			}
			info := &grpc.UnaryServerInfo{FullMethod: methodName}

			// Mock handler
			var handlerCalled bool
			var resultCtx context.Context
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				handlerCalled = true
				resultCtx = ctx
				return "response", nil
			}

			// Call interceptor
			resp, err := unaryInterceptor(ctx, "request", info, handler)

			// Verify results
			if tt.expectErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectedCode, st.Code())
				assert.False(t, handlerCalled)
			} else {
				require.NoError(t, err)
				assert.True(t, handlerCalled)
				assert.Equal(t, "response", resp)

				// Check if claims are in context
				claims := GetClaimsFromContext(resultCtx)
				if tt.expectedClaims {
					require.NotNil(t, claims)
					assert.Equal(t, "user123", claims.RegisteredClaims.Subject)
				} else {
					assert.Nil(t, claims)
				}
			}
		})
	}
}

type mockServerStream struct {
	grpc.ServerStream
	ctx    context.Context
	called bool
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func TestStreamInterceptor(t *testing.T) {
	validToken := "validToken123"
	invalidToken := "invalidToken456"

	tests := []struct {
		name           string
		token          string
		options        []Option
		method         string
		expectErr      bool
		expectedCode   codes.Code
		expectedClaims bool
	}{
		{
			name:           "valid token",
			token:          validToken,
			expectErr:      false,
			expectedClaims: true,
		},
		{
			name:         "invalid token",
			token:        invalidToken,
			expectErr:    true,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "missing token",
			token:        "",
			expectErr:    true,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:  "optional credentials with missing token",
			token: "",
			options: []Option{
				WithCredentialsOptional(true),
			},
			expectErr:      false,
			expectedClaims: false,
		},
		{
			name:   "excluded method",
			token:  "",
			method: "/test.service/ExcludedStreamMethod",
			options: []Option{
				WithExclusionMethods([]string{"/test.service/ExcludedStreamMethod"}),
			},
			expectErr:      false,
			expectedClaims: false,
		},
		{
			name:  "WithTokenExtractor",
			token: "", // Token extracted from context
			options: []Option{
				WithTokenExtractor(func(ctx context.Context) (string, error) {
					return validToken, nil
				}),
			},
			expectErr:      false,
			expectedClaims: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create interceptor with mock validator
			interceptor := New(mockValidateToken(validToken), tt.options...)
			streamInterceptor := interceptor.StreamServerInterceptor()

			// Create context with token if provided
			ctx := context.Background()
			if tt.token != "" {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+tt.token))
			}

			// Set method name, default unless overridden
			methodName := "/test.service/TestStreamMethod"
			if tt.method != "" {
				methodName = tt.method
			}
			info := &grpc.StreamServerInfo{FullMethod: methodName}

			// Create mock stream
			mockStream := &mockServerStream{ctx: ctx}

			// Create handler
			var handlerCalled bool
			var streamCtx context.Context
			handler := func(srv interface{}, stream grpc.ServerStream) error {
				handlerCalled = true
				streamCtx = stream.Context()
				return nil
			}

			// Call interceptor
			err := streamInterceptor(nil, mockStream, info, handler)

			// Verify results
			if tt.expectErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectedCode, st.Code())
				require.False(t, handlerCalled, "Handler should not be called on failure")
			} else {
				require.NoError(t, err)
				assert.True(t, handlerCalled, "Handler should be called on success")

				// Validate claims in context
				claims := GetClaimsFromContext(streamCtx)
				if tt.expectedClaims {
					require.NotNil(t, claims, "Claims should be present")
					assert.Equal(t, "user123", claims.RegisteredClaims.Subject, "Unexpected claim subject")
				} else {
					assert.Nil(t, claims, "Claims should not be present")
				}
			}
		})
	}
}

func TestExtractors(t *testing.T) {
	t.Run("MetadataTokenExtractor", func(t *testing.T) {
		t.Run("If metadata is missing, it should return an empty token", func(t *testing.T) {
			ctx := context.Background()
			token, err := MetadataTokenExtractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "", token)
		})
		t.Run("If metadata is present, it should return the token", func(t *testing.T) {
			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer validToken123"),
			)
			token, err := MetadataTokenExtractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "validToken123", token)

			// Test invalid format
			ctx = metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "NotBearer token"),
			)
			_, err = MetadataTokenExtractor(ctx)
			require.Error(t, err)

			// Test missing metadata
			ctx = context.Background()
			token, err = MetadataTokenExtractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "", token)
		})
		t.Run("if context is empty it should return an empty token", func(t *testing.T) {
			ctx := context.Background()
			token, err := MetadataTokenExtractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "", token)
		})
		t.Run("if Authorization header is missing, it should return an empty token", func(t *testing.T) {
			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("other", "value"),
			)
			token, err := MetadataTokenExtractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "", token)
		})
	})

	t.Run("MetadataFieldTokenExtractor", func(t *testing.T) {
		t.Run("If field is missing, it should return an empty token", func(t *testing.T) {
			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("other", "value"),
			)
			token, err := MetadataFieldTokenExtractor("token")(ctx)
			require.NoError(t, err)
			assert.Equal(t, "", token)
		})
		t.Run("if field is present, it should return the token", func(t *testing.T) {
			// Test valid token
			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("token", "customToken123"),
			)
			extractor := MetadataFieldTokenExtractor("token")
			token, err := extractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "customToken123", token)

			// Test missing field
			ctx = metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("other", "value"),
			)
			token, err = extractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "", token)
		})
		t.Run("if context is empty it should return an empty token", func(t *testing.T) {
			ctx := context.Background()
			token, err := MetadataFieldTokenExtractor("token")(ctx)
			require.NoError(t, err)
			assert.Equal(t, "", token)
		})
	})

	t.Run("MultiTokenExtractor", func(t *testing.T) {
		t.Run("If first extractor returns a token, it should be used", func(t *testing.T) {
			// Create context with authorization but no token field
			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer authToken"),
			)

			// Create extractors
			authExtractor := MetadataTokenExtractor
			tokenExtractor := MetadataFieldTokenExtractor("token")
			multiExtractor := MultiGRPCTokenExtractor(tokenExtractor, authExtractor)

			// Test that it finds the token from authorization
			token, err := multiExtractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "authToken", token)

			// Create context with token field but no authorization
			ctx = metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("token", "fieldToken"),
			)

			// Test that it finds the token from token field
			token, err = multiExtractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "fieldToken", token)
		})
		t.Run("if extractor does not return a token, it should try the next one", func(t *testing.T) {
			// Create context with no token
			ctx := context.Background()

			// Create extractors
			noopExtractor := func(ctx context.Context) (string, error) {
				return "", nil
			}
			erringExtractor := func(ctx context.Context) (string, error) {
				return "", errors.New("extraction failure")
			}
			extractor := MultiGRPCTokenExtractor(noopExtractor, erringExtractor)

			// Test that it returns an error
			token, err := extractor(ctx)
			require.Error(t, err)
			assert.Equal(t, "extraction failure", err.Error())
			assert.Equal(t, "", token)
		})
		t.Run("if Extractor is empty, it should return an empty token", func(t *testing.T) {
			// Create context with no token
			ctx := context.Background()

			// Create extractor
			extractor := MultiGRPCTokenExtractor()

			// Test that it returns an empty token
			token, err := extractor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "", token)
		})
	})
}

func TestGetClaimsFromContext(t *testing.T) {
	// Test with valid claims
	expectedClaims := &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{
			Subject: "user123",
		},
	}

	ctx := context.WithValue(context.Background(), jwtmiddleware.ContextKey{}, expectedClaims)

	claims := GetClaimsFromContext(ctx)
	require.NotNil(t, claims)
	assert.Equal(t, expectedClaims.RegisteredClaims.Subject, claims.RegisteredClaims.Subject)

	// Test without claims
	ctx = context.Background()
	claims = GetClaimsFromContext(ctx)
	assert.Nil(t, claims)
}

func TestRequireClaimsFromContext(t *testing.T) {
	// Test with valid claims
	expectedClaims := &validator.ValidatedClaims{
		RegisteredClaims: validator.RegisteredClaims{
			Subject: "user123",
		},
	}

	ctx := context.WithValue(context.Background(), jwtmiddleware.ContextKey{}, expectedClaims)

	claims, err := RequireClaimsFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, expectedClaims.RegisteredClaims.Subject, claims.RegisteredClaims.Subject)

	// Test without claims
	ctx = context.Background()
	claims, err = RequireClaimsFromContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingClaims)
	assert.Nil(t, claims)

	// Test with invalid claims (wrong type)
	invalidClaims := map[string]interface{}{"sub": "user123"}
	ctx = context.WithValue(context.Background(), jwtmiddleware.ContextKey{}, invalidClaims)

	claims, err = RequireClaimsFromContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidClaims)
	assert.Nil(t, claims)
}

func TestExclusionChecker(t *testing.T) {
	methods := []string{"/service/Method1", "/service/Method2"}

	interceptor := New(
		mockValidateToken("valid"),
		WithExclusionMethods(methods),
		WithExclusionChecker(func(method string) bool {
			for _, m := range methods {
				if m == method {
					return true
				}
			}
			return false
		}),
	)

	// Should exclude Method1
	assert.True(t, interceptor.exclusionChecker("/service/Method1"))

	// Should exclude Method2
	assert.True(t, interceptor.exclusionChecker("/service/Method2"))

	// Should not exclude Method3
	assert.False(t, interceptor.exclusionChecker("/service/Method3"))
}
