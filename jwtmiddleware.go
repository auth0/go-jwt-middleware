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
type ValidateToken func(string) (interface{}, error)

type JWTMiddleware struct {
	validateToken       ValidateToken
	contextKey          string
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

// WithContextKey sets up the property to be used in the request where the user
// information from a validated JWT will be stored.
// Default value: "user"
func WithContextKey(k string) Option {
	return func(m *JWTMiddleware) {
		m.contextKey = k
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

// WithCredentialsOptions sets up if credentials are optional or not. If set to
// true then an empty token will be considered valid.
// Default value: false
func WithCredentialsOptional(value bool) Option {
	return func(m *JWTMiddleware) {
		m.credentialsOptional = value
	}
}

// WithTokenExtractor sets up the function which extracts the JWT to be
// validated from the request.
// Default: FromAuthHeader (i.e., from Authorization header as bearer token)
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

// New constructs a new Secure instance with supplied options.
func New(opts ...Option) *JWTMiddleware {
	m := &JWTMiddleware{
		validateToken:       func(string) (interface{}, error) { panic("not implemented") },
		contextKey:          "user",
		errorHandler:        DefaultErrorHandler,
		credentialsOptional: false,
		tokenExtractor:      FromAuthHeader,
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
	if errors.Is(err, ErrJWTMissing) {
		http.Error(w, "", http.StatusBadRequest)
		return
	} else if errors.Is(err, ErrJWTInvalid) {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	http.Error(w, "", http.StatusInternalServerError)
}

// HandlerWithNext is a special implementation for Negroni, but could be used elsewhere.
func (m *JWTMiddleware) HandlerWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	err := m.CheckJWT(r)

	if err != nil {
		m.errorHandler(w, r, err)
		return
	}

	if next != nil {
		next(w, r)
	}
}

func (m *JWTMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.HandlerWithNext(w, r, h.ServeHTTP)
	})
}

// FromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the token from the Authorization header.
func FromAuthHeader(r *http.Request) (string, error) {
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

// FromParameter returns a function that extracts the token from the specified
// query string parameter
func FromParameter(param string) TokenExtractor {
	return func(r *http.Request) (string, error) {
		return r.URL.Query().Get(param), nil
	}
}

// FromFirst returns a function that runs multiple TokenExtractors and takes
// the first token it finds
func FromFirst(extractors ...TokenExtractor) TokenExtractor {
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

func (m *JWTMiddleware) CheckJWT(r *http.Request) error {
	if !m.validateOnOptions {
		if r.Method == http.MethodOptions {
			return nil
		}
	}

	token, err := m.tokenExtractor(r)
	if err != nil {
		// this is not ErrJWTMissing because an error here means that
		// the tokenExtractor had an error and _not_ that the token was
		// missing.
		return fmt.Errorf("error extracting token: %w", err)
	}
	if token == "" {
		if m.credentialsOptional {
			return nil
		}

		return ErrJWTMissing
	}

	validToken, err := m.validateToken(token)
	if err != nil {
		return &invalidError{details: err}
	}

	newRequest := r.WithContext(context.WithValue(r.Context(), m.contextKey, validToken))

	// Update the current request with the new context information.
	*r = *newRequest
	return nil
}
