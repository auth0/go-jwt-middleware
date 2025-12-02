package jwtmiddleware

import (
	"errors"
	"net/http"
	"strings"
)

// AuthScheme represents the authorization scheme used in the request.
type AuthScheme string

const (
	// AuthSchemeBearer represents Bearer token authorization.
	AuthSchemeBearer AuthScheme = "bearer"
	// AuthSchemeDPoP represents DPoP token authorization.
	AuthSchemeDPoP AuthScheme = "dpop"
	// AuthSchemeUnknown represents an unknown or missing authorization scheme.
	AuthSchemeUnknown AuthScheme = ""
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
func AuthHeaderTokenExtractor(r *http.Request) (ExtractedToken, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ExtractedToken{}, nil // No error, just no JWT.
	}

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
