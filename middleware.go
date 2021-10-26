package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"
)

// ContextKey is the key used in the request context where the information
// from a validated JWT will be stored.
type ContextKey struct{}

type JWTMiddleware struct {
	validateToken       ValidateToken
	errorHandler        ErrorHandler
	tokenExtractor      TokenExtractor
	credentialsOptional bool
	validateOnOptions   bool
}

// ValidateToken takes in a string JWT and handles making sure it is valid and
// returning the valid token. If it is not valid it will return nil and an
// error message describing why validation failed.
// Inside of ValidateToken is where things like key and alg checking can
// happen. In the default implementation we can add safe defaults for those.
type ValidateToken func(context.Context, string) (interface{}, error)

// New constructs a new JWTMiddleware instance with the supplied options. It
// requires a ValidateToken function to be passed in so it can properly
// validate tokens.
func New(validateToken ValidateToken, opts ...Option) *JWTMiddleware {
	m := &JWTMiddleware{
		validateToken:       validateToken,
		errorHandler:        DefaultErrorHandler,
		credentialsOptional: false,
		tokenExtractor:      AuthHeaderTokenExtractor,
		validateOnOptions:   true,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// CheckJWT is the main middleware function which performs the main logic. It
// is passed an http.Handler which will be called if the JWT passes validation.
func (m *JWTMiddleware) CheckJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if we don't validate on OPTIONS and this is OPTIONS then
		// continue onto next without validating
		if !m.validateOnOptions && r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		token, err := m.tokenExtractor(r)
		if err != nil {
			// this is not ErrJWTMissing because an error here means that
			// the tokenExtractor had an error and _not_ that the token was
			// missing.
			m.errorHandler(w, r, fmt.Errorf("error extracting token: %w", err))
			return
		}

		if token == "" {
			// if credentials are optional continue onto next
			// without validating
			if m.credentialsOptional {
				next.ServeHTTP(w, r)
				return
			}

			// credentials were not optional so we error
			m.errorHandler(w, r, ErrJWTMissing)
			return
		}

		// validate the token using the token validator
		validToken, err := m.validateToken(r.Context(), token)
		if err != nil {
			m.errorHandler(w, r, &invalidError{details: err})
			return
		}

		// no err means we have a valid token, so set it into the
		// context and continue onto next
		r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))
		next.ServeHTTP(w, r)
	})
}
