package grpc

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/metadata"
)

// TokenExtractor extracts JWT tokens from gRPC metadata.
type TokenExtractor func(ctx context.Context) (string, error)

// Extractor errors
var (
	// ErrMultipleAuthHeaders indicates multiple authorization metadata entries were provided.
	ErrMultipleAuthHeaders = errors.New("multiple authorization metadata entries are not allowed")

	// ErrInvalidAuthFormat indicates the authorization metadata format is invalid.
	ErrInvalidAuthFormat = errors.New("invalid authorization metadata format, expected: Bearer <token>")

	// ErrUnsupportedScheme indicates an unsupported authorization scheme was used.
	ErrUnsupportedScheme = errors.New("unsupported authorization scheme, expected: Bearer")
)

// MetadataTokenExtractor extracts JWT from the "authorization" metadata key.
// It supports the "Bearer <token>" format (standard for gRPC).
//
// gRPC normalizes incoming metadata keys to lowercase, so this extractor only
// checks the lowercase "authorization" key.
//
// Return behavior:
//   - ("", nil) when no metadata or no authorization header is present.
//     This is not an error; the core.CheckToken handles missing tokens
//     based on the credentialsOptional configuration.
//   - (token, nil) when a valid Bearer token is extracted.
//   - ("", error) when the authorization header is malformed.
func MetadataTokenExtractor(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", nil // No metadata - let core handle based on credentialsOptional
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", nil // No auth header - let core handle based on credentialsOptional
	}

	if len(authHeaders) > 1 {
		return "", ErrMultipleAuthHeaders
	}

	authHeader := authHeaders[0]

	// Parse "Bearer <token>"
	parts := strings.Fields(authHeader)
	if len(parts) != 2 {
		return "", ErrInvalidAuthFormat
	}

	scheme := strings.ToLower(parts[0])
	if scheme != "bearer" {
		return "", ErrUnsupportedScheme
	}

	return parts[1], nil
}
