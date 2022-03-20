package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type GinJWTMiddleware struct {
	validateToken       ValidateToken
	errorHandler        GinErrorHandler
	tokenExtractor      TokenExtractor
	credentialsOptional bool
	validateOnOptions   bool
}

// New constructs a new JWTMiddleware instance with the supplied options.
// It requires a ValidateToken function to be passed in, so it can
// properly validate tokens.
func NewGin(validateToken ValidateToken, opts ...GinOption) *GinJWTMiddleware {
	m := &GinJWTMiddleware{
		validateToken:       validateToken,
		errorHandler:        DefaultGinErrorHandler,
		credentialsOptional: false,
		tokenExtractor:      AuthHeaderTokenExtractor,
		validateOnOptions:   true,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// CheckJWTGin is the main JWTMiddleware function which performs the main logic with Gin support. It
// is passed a http.Handler which will be called if the JWT passes validation.
func (m *GinJWTMiddleware) CheckJWTGin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If we don't validate on OPTIONS and this is OPTIONS
		// then continue onto next without validating.
		if !m.validateOnOptions && c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		token, err := m.tokenExtractor(c.Request)
		if err != nil {
			// This is not ErrJWTMissing because an error here means that the
			// tokenExtractor had an error and _not_ that the token was missing.
			m.errorHandler(c, fmt.Errorf("error extracting token: %w", err))
			return
		}

		if token == "" {
			// If credentials are optional continue
			// onto next without validating.
			if m.credentialsOptional {
				c.Next()
				return
			}

			// Credentials were not optional so we error.
			m.errorHandler(c, ErrJWTMissing)
			return
		}

		// Validate the token using the token validator.
		validToken, err := m.validateToken(c.Request.Context(), token)
		if err != nil {
			m.errorHandler(c, &invalidError{details: err})
			return
		}

		// No err means we have a valid token, so set
		// it into the context and continue onto next.
		c.Request = c.Request.Clone(context.WithValue(c.Request.Context(), ContextKey{}, validToken))
		c.Next()
	}
}
