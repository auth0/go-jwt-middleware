package jwtmiddleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrJWTMissing = errors.New("jwt missing")
	ErrJWTInvalid = errors.New("jwt invalid")
)

// ContextKey is the key used in the request context where the information
// from a validated JWT will be stored.
type ContextKey struct{}

// invalidError handles wrapping a JWT validation error with the concrete error
// ErrJWTInvalid. We do not expose this publicly because the interface methods
// of Is and Unwrap should give the user all they need.
type invalidError struct {
	details error
}

// Is allows the error to support equality to ErrJWTInvalid.
func (e *invalidError) Is(target error) bool {
	return target == ErrJWTInvalid
}

func (e *invalidError) Error() string {
	return fmt.Sprintf("%s: %s", ErrJWTInvalid, e.details)
}

// Unwrap allows the error to support equality to the underlying error and not
// just ErrJWTInvalid.
func (e *invalidError) Unwrap() error {
	return e.details
}

// ErrorHandler is a handler which is called when an error occurs in the
// middleware. Among some general errors, this handler also determines the
// response of the middleware when a token is not found or is invalid. The err
// can be checked to be ErrJWTMissing or ErrJWTInvalid for specific cases. The
// default handler will return a status code of 400 for ErrJWTMissing, 401 for
// ErrJWTInvalid, and 500 for all other errors. If you implement your own
// ErrorHandler you MUST take into consideration the error types as not
// properly responding to them or having a poorly implemented handler could
// result in the middleware not functioning as intended.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// TokenExtractor is a function that takes a request as input and returns
// either a token or an error.  An error should only be returned if an attempt
// to specify a token was found, but the information was somehow incorrectly
// formed.  In the case where a token is simply not present, this should not
// be treated as an error.  An empty string should be returned in that case.
type TokenExtractor func(r *http.Request) (string, error)

// ValidateToken takes in a string JWT and handles making sure it is valid and
// returning the valid token. If it is not valid it will return nil and an
// error message describing why validation failed.
// Inside of ValidateToken is where things like key and alg checking can
// happen. In the default implementation we can add safe defaults for those.
type ValidateToken func(context.Context, string) (interface{}, error)

type JWTMiddleware struct {
	validateToken       ValidateToken
	errorHandler        ErrorHandler
	credentialsOptional bool
	tokenExtractor      TokenExtractor
	validateOnOptions   bool
}

// Option is how options for the middleware are setup.
type Option func(*JWTMiddleware)

// WithValidateToken sets up the function to be used to validate all tokens.
// See the ValidateToken type for more information.
// Default: TODO: after merge into `v2`
func WithValidateToken(vt ValidateToken) Option {
	return func(m *JWTMiddleware) {
		m.validateToken = vt
	}
}

// WithErrorHandler sets the handler which is called when there are errors in
// the middleware. See the ErrorHandler type for more information.
// Default value: DefaultErrorHandler
func WithErrorHandler(h ErrorHandler) Option {
	return func(m *JWTMiddleware) {
		m.errorHandler = h
	}
}

// WithCredentialsOptional sets up if credentials are optional or not. If set
// to true then an empty token will be considered valid.
// Default value: false
func WithCredentialsOptional(value bool) Option {
	return func(m *JWTMiddleware) {
		m.credentialsOptional = value
	}
}

// WithTokenExtractor sets up the function which extracts the JWT to be
// validated from the request.
// Default: AuthHeaderTokenExtractor
func WithTokenExtractor(e TokenExtractor) Option {
	return func(m *JWTMiddleware) {
		m.tokenExtractor = e
	}
}

// WithValidateOnOptions sets up if OPTIONS requests should have their JWT
// validated or not.
// Default: true
func WithValidateOnOptions(value bool) Option {
	return func(m *JWTMiddleware) {
		m.validateOnOptions = value
	}
}

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

// DefaultErrorHandler is the default error handler implementation for the
// middleware. If an error handler is not provided via the WithErrorHandler
// option this will be used.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrJWTMissing):
		w.WriteHeader(http.StatusBadRequest)
	case errors.Is(err, ErrJWTInvalid):
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

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
		newRequest := r.WithContext(context.WithValue(r.Context(), ContextKey{}, validToken))
		r = newRequest
		next.ServeHTTP(w, r)
	})
}
