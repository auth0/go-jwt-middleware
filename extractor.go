package jwtmiddleware

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

// TokenExtractor is a function that takes a request as input and returns
// either a token or an error.  An error should only be returned if an attempt
// to specify a token was found, but the information was somehow incorrectly
// formed.  In the case where a token is simply not present, this should not
// be treated as an error.  An empty string should be returned in that case.
type TokenExtractor func(r *http.Request) (string, error)

// AuthHeaderTokenExtractor is a TokenExtractor that takes a request and
// extracts the token from the Authorization header.
func AuthHeaderTokenExtractor(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no JWT
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// CookieTokenExtractor builds a TokenExtractor that takes a request and
// extracts the token from the cookie using the passed in cookieName.
func CookieTokenExtractor(cookieName string) TokenExtractor {
	return func(r *http.Request) (string, error) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return "", err
		}

		if cookie != nil {
			return cookie.Value, nil
		}

		return "", nil // No error, just no JWT
	}
}

// ParameterTokenExtractor returns a TokenExtractor that extracts the token
// from the specified query string parameter
func ParameterTokenExtractor(param string) TokenExtractor {
	return func(r *http.Request) (string, error) {
		return r.URL.Query().Get(param), nil
	}
}

// MultiTokenExtractor returns a TokenExtractor that runs multiple
// TokenExtractors and takes the TokenExtractor that does not return an empty
// token. If a TokenExtractor returns an error that error is immediately
// returned.
func MultiTokenExtractor(extractors ...TokenExtractor) TokenExtractor {
	return func(r *http.Request) (string, error) {
		for _, ex := range extractors {
			token, err := ex(r)
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
