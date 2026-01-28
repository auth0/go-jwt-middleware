package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

const validToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwiYXVkIjoidGVzdEF1ZGllbmNlIn0.test"

func TestMetadataTokenExtractor_ValidToken(t *testing.T) {
	md := metadata.Pairs("authorization", "Bearer "+validToken)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := MetadataTokenExtractor(ctx)

	assert.NoError(t, err)
	assert.Equal(t, validToken, token)
}

func TestMetadataTokenExtractor_NoMetadata(t *testing.T) {
	ctx := context.Background()

	token, err := MetadataTokenExtractor(ctx)

	assert.NoError(t, err)
	assert.Empty(t, token)
}

func TestMetadataTokenExtractor_NoAuthorizationHeader(t *testing.T) {
	md := metadata.Pairs("other-header", "value")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := MetadataTokenExtractor(ctx)

	assert.NoError(t, err)
	assert.Empty(t, token)
}

func TestMetadataTokenExtractor_MultipleAuthHeaders(t *testing.T) {
	md := metadata.Pairs(
		"authorization", "Bearer token1",
		"authorization", "Bearer token2",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := MetadataTokenExtractor(ctx)

	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "multiple authorization metadata entries")
}

func TestMetadataTokenExtractor_InvalidFormat_NoBearer(t *testing.T) {
	md := metadata.Pairs("authorization", "token123")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := MetadataTokenExtractor(ctx)

	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "invalid authorization metadata format")
}

func TestMetadataTokenExtractor_InvalidFormat_OnlyBearer(t *testing.T) {
	md := metadata.Pairs("authorization", "Bearer")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := MetadataTokenExtractor(ctx)

	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "invalid authorization metadata format")
}

func TestMetadataTokenExtractor_InvalidFormat_TooManyParts(t *testing.T) {
	md := metadata.Pairs("authorization", "Bearer token extra")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := MetadataTokenExtractor(ctx)

	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "invalid authorization metadata format")
}

func TestMetadataTokenExtractor_UnsupportedScheme(t *testing.T) {
	md := metadata.Pairs("authorization", "Basic dXNlcjpwYXNz")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := MetadataTokenExtractor(ctx)

	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "unsupported authorization scheme")
}

func TestMetadataTokenExtractor_CaseInsensitiveBearer(t *testing.T) {
	testCases := []struct {
		name   string
		scheme string
	}{
		{"lowercase", "bearer"},
		{"uppercase", "BEARER"},
		{"mixedcase", "BeArEr"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", tc.scheme+" "+validToken)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			token, err := MetadataTokenExtractor(ctx)

			assert.NoError(t, err)
			assert.Equal(t, validToken, token)
		})
	}
}

func TestMetadataTokenExtractor_ExtraWhitespace(t *testing.T) {
	md := metadata.Pairs("authorization", "Bearer   "+validToken)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := MetadataTokenExtractor(ctx)

	assert.NoError(t, err)
	assert.Equal(t, validToken, token)
}
