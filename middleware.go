package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"
)

// ContextKey is the key used in the request
// context where the information from a
// validated JWT will be stored.
type ContextKey struct{}

type JWTMiddleware struct {
	validateToken       ValidateToken
	errorHandler        ErrorHandler
	tokenExtractor      TokenExtractor
	credentialsOptional bool
	validateOnOptions   bool
	exclusionUrlHandler ExclusionUrlHandler
}

type JWTMiddlewares []*JWTMiddleware

// ValidateToken takes in a string JWT and makes sure it is valid and
// returns the valid token. If it is not valid it will return nil and
// an error message describing why validation failed.
// Inside ValidateToken things like key and alg checking can happen.
// In the default implementation we can add safe defaults for those.
type ValidateToken func(context.Context, string) (interface{}, error)

// ExclusionUrlHandler is a function that takes in a http.Request and returns
// true if the request should be excluded from JWT validation.
type ExclusionUrlHandler func(r *http.Request) bool

// New constructs a new JWTMiddleware instance with the supplied options.
// It requires a ValidateToken function to be passed in, so it can
// properly validate tokens.
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

// CheckJWT is the main JWTMiddleware function which performs the main logic. It
// is passed a http.Handler which will be called if the JWT passes validation.
func (m *JWTMiddleware) CheckJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If there's an exclusion handler and the URL matches, skip JWT validation
		if m.exclusionUrlHandler != nil && m.exclusionUrlHandler(r) {
			next.ServeHTTP(w, r)
			return
		}
		// If we don't validate on OPTIONS and this is OPTIONS
		// then continue onto next without validating.
		if !m.validateOnOptions && r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		token, err := m.tokenExtractor(r)
		if err != nil {
			// This is not ErrJWTMissing because an error here means that the
			// tokenExtractor had an error and _not_ that the token was missing.
			m.errorHandler(w, r, fmt.Errorf("error extracting token: %w", err))
			return
		}

		if token == "" {
			// If credentials are optional continue
			// onto next without validating.
			if m.credentialsOptional {
				next.ServeHTTP(w, r)
				return
			}

			// Credentials were not optional so we error.
			m.errorHandler(w, r, ErrJWTMissing)
			return
		}

		// Validate the token using the token validator.
		validToken, err := m.validateToken(r.Context(), token)
		if err != nil {
			m.errorHandler(w, r, &invalidError{details: err})
			return
		}

		// No err means we have a valid token, so set
		// it into the context and continue onto next.
		r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))
		next.ServeHTTP(w, r)
	})
}

// CheckJWTMulti is the main JWTMiddleware function which performs the main logic. It
// is passed a http.Handler which will be called if the JWT passes validation for one
// of the JWTMiddleware configs in a slice.
func (mm JWTMiddlewares) CheckJWTMulti(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < len(mm); i++ {
			m := mm[i]
			isLast := true
			if (i + 1) == len(mm) {
				isLast = true
			} else {
				isLast = false
			}
			// If we don't validate on OPTIONS and this is OPTIONS
			// then continue onto next without validating.
			if !m.validateOnOptions && r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			token, err := m.tokenExtractor(r)
			if err != nil {
				// This is not ErrJWTMissing because an error here means that the
				// tokenExtractor had an error and _not_ that the token was missing.
				m.errorHandler(w, r, fmt.Errorf("error extracting token: %w", err))
				return
			}

			if token == "" {
				// If credentials are optional continue
				// onto next without validating.
				if m.credentialsOptional {
					next.ServeHTTP(w, r)
					return
				}

				if !isLast {
					continue
				}
				// Credentials were not optional so we error.
				m.errorHandler(w, r, ErrJWTMissing)
				return
			}

			// Validate the token using the token validator.
			validToken, err := m.validateToken(r.Context(), token)
			if err != nil {
				if !isLast {
					continue
				}
				m.errorHandler(w, r, &invalidError{details: err})
				return
			}

			// No err means we have a valid token, so set
			// it into the context and continue onto next.
			r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))
			next.ServeHTTP(w, r)
			return
		}
	})
}
