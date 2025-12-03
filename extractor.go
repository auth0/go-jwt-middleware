package jwtmiddleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/auth0/go-jwt-middleware/v3/core"
)

// AuthScheme is an alias for core.AuthScheme for backward compatibility.
// New code should use core.AuthScheme directly.
type AuthScheme = core.AuthScheme

const (
	// AuthSchemeBearer represents Bearer token authorization.
	AuthSchemeBearer = core.AuthSchemeBearer
	// AuthSchemeDPoP represents DPoP token authorization.
	AuthSchemeDPoP = core.AuthSchemeDPoP
	// AuthSchemeUnknown represents an unknown or missing authorization scheme.
	AuthSchemeUnknown = core.AuthSchemeUnknown
)

// ExtractedToken holds both the extracted token and the authorization scheme used.
// This allows the middleware to enforce that DPoP scheme requires a DPoP proof.
type ExtractedToken struct {
	Token  string
	Scheme AuthScheme
}

// TokenExtractor is a function that takes a request as input and returns
// an ExtractedToken containing both the token and its authorization scheme,
// or an error. An error should only be returned if an attempt to specify a
// token was found, but the information was somehow incorrectly formed.
// In the case where a token is simply not present, this should not be treated
// as an error. An empty ExtractedToken should be returned in that case.
//
// For extractors that don't have scheme information (cookies, query params),
// the Scheme field should be set to AuthSchemeUnknown.
type TokenExtractor func(r *http.Request) (ExtractedToken, error)

// AuthHeaderTokenExtractor is a TokenExtractor that takes a request
// and extracts the token and scheme from the Authorization header.
// Supports both "Bearer" and "DPoP" authorization schemes.
//
// Security: Rejects requests with multiple Authorization headers per RFC 9449.
func AuthHeaderTokenExtractor(r *http.Request) (ExtractedToken, error) {
	// Check for multiple Authorization headers (security issue)
	// Per RFC 9449 Section 7.2, having both Bearer and DPoP Authorization headers
	// is a malformed request that should be rejected
	authHeaders := r.Header.Values("Authorization")
	if len(authHeaders) == 0 {
		return ExtractedToken{}, nil // No error, just no JWT.
	}

	if len(authHeaders) > 1 {
		return ExtractedToken{}, errors.New("multiple Authorization headers are not allowed")
	}

	authHeader := authHeaders[0]
	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 {
		return ExtractedToken{}, errors.New("authorization header format must be Bearer {token} or DPoP {token}")
	}

	// Accept both "Bearer" and "DPoP" schemes (case-insensitive)
	scheme := strings.ToLower(authHeaderParts[0])
	var authScheme AuthScheme
	switch scheme {
	case "bearer":
		authScheme = AuthSchemeBearer
	case "dpop":
		authScheme = AuthSchemeDPoP
	default:
		return ExtractedToken{}, errors.New("authorization header format must be Bearer {token} or DPoP {token}")
	}

	return ExtractedToken{
		Token:  authHeaderParts[1],
		Scheme: authScheme,
	}, nil
}

// CookieTokenExtractor builds a TokenExtractor that takes a request and
// extracts the token from the cookie using the passed in cookieName.
// Note: Cookies do not carry scheme information, so Scheme will be AuthSchemeUnknown.
func CookieTokenExtractor(cookieName string) TokenExtractor {
	return func(r *http.Request) (ExtractedToken, error) {
		if cookieName == "" {
			return ExtractedToken{}, errors.New("cookie name cannot be empty")
		}

		cookie, err := r.Cookie(cookieName)
		if errors.Is(err, http.ErrNoCookie) {
			return ExtractedToken{}, nil // No cookie, then no JWT, so no error.
		}
		if err != nil {
			// Defensive: r.Cookie() rarely returns non-ErrNoCookie errors in practice,
			// but we handle them properly for robustness. The http package's cookie
			// parsing is very lenient and typically only returns ErrNoCookie.
			return ExtractedToken{}, err
		}

		return ExtractedToken{
			Token:  cookie.Value,
			Scheme: AuthSchemeUnknown, // Cookies don't have scheme info
		}, nil
	}
}

// ParameterTokenExtractor returns a TokenExtractor that extracts
// the token from the specified query string parameter.
// Note: Query parameters do not carry scheme information, so Scheme will be AuthSchemeUnknown.
func ParameterTokenExtractor(param string) TokenExtractor {
	return func(r *http.Request) (ExtractedToken, error) {
		if param == "" {
			return ExtractedToken{}, errors.New("parameter name cannot be empty")
		}
		token := r.URL.Query().Get(param)
		if token == "" {
			return ExtractedToken{}, nil
		}
		return ExtractedToken{
			Token:  token,
			Scheme: AuthSchemeUnknown, // Query params don't have scheme info
		}, nil
	}
}

// MultiTokenExtractor returns a TokenExtractor that runs multiple TokenExtractors
// and takes the one that does not return an empty token. If a TokenExtractor
// returns an error that error is immediately returned.
func MultiTokenExtractor(extractors ...TokenExtractor) TokenExtractor {
	return func(r *http.Request) (ExtractedToken, error) {
		for _, ex := range extractors {
			result, err := ex(r)
			if err != nil {
				return ExtractedToken{}, err
			}

			if result.Token != "" {
				return result, nil
			}
		}
		return ExtractedToken{}, nil
	}
}
