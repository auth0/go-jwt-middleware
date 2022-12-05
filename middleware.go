package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"
	"os"
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
}

type JWTMiddlewares []*JWTMiddleware

// ValidateToken takes in a string JWT and makes sure it is valid and
// returns the valid token. If it is not valid it will return nil and
// an error message describing why validation failed.
// Inside ValidateToken things like key and alg checking can happen.
// In the default implementation we can add safe defaults for those.
type ValidateToken func(context.Context, string) (interface{}, error)

func IsDebug() bool {
	_, exists := os.LookupEnv("DEBUG")
	return exists
}

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
	if IsDebug() {
		fmt.Println("CheckJWTMulti")
		fmt.Println(mm)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		broken := false
		for i := 0; i < len(mm); i++ {
			m := mm[i]
			if IsDebug() {
				fmt.Println("\ncurrent conf:")
				fmt.Println(m.validateToken)
			}
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
				broken = true
				break
			}

			token, err := m.tokenExtractor(r)
			if err != nil {
				// This is not ErrJWTMissing because an error here means that the
				// tokenExtractor had an error and _not_ that the token was missing.
				m.errorHandler(w, r, fmt.Errorf("error extracting token: %w", err))
				broken = true
				break
			}

			if token == "" {
				// If credentials are optional continue
				// onto next without validating.
				if m.credentialsOptional {
					next.ServeHTTP(w, r)
					broken = true
					break
				}

				if !isLast {
					if IsDebug() {
						fmt.Println("token empty, but not last m")
					}
					continue
				} else {
					if IsDebug() {
						fmt.Println("token empty, is last m")
					}
				}
				// Credentials were not optional so we error.
				m.errorHandler(w, r, ErrJWTMissing)
				broken = true
				break
			}

			// Validate the token using the token validator.
			validToken, err := m.validateToken(r.Context(), token)
			if err != nil {
				if !isLast {
					if IsDebug() {
						fmt.Println("\ntoken not valid, but not last m")
					}
					continue
				} else {
					if IsDebug() {
						fmt.Println("\ntoken not valid, is last m")
					}
				}
				m.errorHandler(w, r, &invalidError{details: err})
				broken = true
				break
			}

			// No err means we have a valid token, so set
			// it into the context and continue onto next.
			r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))
			next.ServeHTTP(w, r)
			broken = true
			break
		}
		if broken {
			if IsDebug() {
				fmt.Println("break")
			}
			return
		} else {
			if IsDebug() {
				fmt.Println("not break")
			}
		}
	})
}
