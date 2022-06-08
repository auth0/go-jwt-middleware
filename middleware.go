package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// ContextKey is the key used in the request
// context where the information from a
// validated JWT will be stored.
type ContextKey struct{}

// JWTMiddleware is an HTTP middleware for authentication using JWT
type JWTMiddleware struct {
	validateToken       ValidateToken
	errorHandler        ErrorHandler
	tokenExtractor      TokenExtractor
	credentialsOptional bool
	validateOnOptions   bool
	tracer              trace.Tracer
}

// ValidateToken takes in a string JWT and makes sure it is valid and
// returns the valid token. If it is not valid it will return nil and
// an error message describing why validation failed.
// Inside ValidateToken things like key and alg checking can happen.
// In the default implementation we can add safe defaults for those.
type ValidateToken func(context.Context, string) (interface{}, error)

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
		tracer:              otel.Tracer("auth0"),
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
		ctx, span := m.tracer.Start(r.Context(), "CheckJWT")
		defer span.End()

		// If we don't validate on OPTIONS and this is OPTIONS
		// then continue onto next without validating.
		if !m.validateOnOptions && r.Method == http.MethodOptions {
			// Force-finish the span so it doesn't run in the following middleware
			span.End()

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
				// Force-finish the span so it doesn't run in the following middleware
				span.End()

				next.ServeHTTP(w, r)
				return
			}

			// Credentials were not optional so we error.
			m.errorHandler(w, r, ErrJWTMissing)
			return
		}

		// Validate the token using the token validator.
		validToken, err := m.validateToken(ctx, token)
		if err != nil {
			m.errorHandler(w, r, &invalidError{details: err})
			return
		}

		// No err means we have a valid token, so set
		// it into the context and continue onto next.
		r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))

		// Force-finish the span so it doesn't run in the following middleware
		span.End()

		next.ServeHTTP(w, r)
	})
}
