package grpcjwt

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/metadata"
)

// GRPCTokenExtractor defines a function that extracts a token from gRPC metadata.
type GRPCTokenExtractor func(ctx context.Context) (string, error)

// MetadataTokenExtractor extracts the JWT token from the "authorization" metadata field.
func MetadataTokenExtractor(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", nil // No metadata, so no JWT.
	}

	values := md.Get("authorization")
	if len(values) == 0 || values[0] == "" {
		return "", nil // No JWT provided.
	}

	authParts := strings.Fields(values[0])
	if len(authParts) != 2 || strings.ToLower(authParts[0]) != "bearer" {
		return "", errors.New("authorization header format must be 'Bearer {token}'")
	}

	return authParts[1], nil
}

// MetadataFieldTokenExtractor extracts the JWT token from a specified metadata field.
func MetadataFieldTokenExtractor(field string) GRPCTokenExtractor {
	return func(ctx context.Context) (string, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return "", nil // No metadata, so no JWT.
		}

		values := md.Get(field)
		if len(values) == 0 || values[0] == "" {
			return "", nil // No JWT provided.
		}

		return values[0], nil
	}
}

// MultiGRPCTokenExtractor runs multiple GRPCTokenExtractors and returns the first valid token.
func MultiGRPCTokenExtractor(extractors ...GRPCTokenExtractor) GRPCTokenExtractor {
	return func(ctx context.Context) (string, error) {
		for _, ex := range extractors {
			token, err := ex(ctx)
			if err != nil {
				return "", err
			}
			if token != "" {
				return token, nil
			}
		}
		return "", nil
	}
}
