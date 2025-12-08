package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

var (
	// The signing key for the token.
	signingKey = []byte("secret")

	// The issuer of our token.
	issuer = "go-jwt-middleware-example"

	// The audience of our token.
	audience = []string{"audience-example"}

	// Our token must be signed using this data.
	keyFunc = func(ctx context.Context) (interface{}, error) {
		return signingKey, nil
	}
)

// checkJWT is an echo.HandlerFunc middleware
// that will check the validity of our JWT.
func checkJWT(next echo.HandlerFunc) echo.HandlerFunc {
	// Set up the validator.
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience),
		// WithCustomClaims now uses generics - no need to return interface type
		validator.WithCustomClaims(func() *CustomClaimsExample {
			return &CustomClaimsExample{}
		}),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Encountered error while validating JWT: %v", err)
	}

	// Set up the middleware using pure options pattern
	middleware, err := jwtmiddleware.New(
		jwtmiddleware.WithValidator(jwtValidator),
		jwtmiddleware.WithErrorHandler(errorHandler),
	)
	if err != nil {
		log.Fatalf("failed to set up the middleware: %v", err)
	}

	return func(ctx echo.Context) error {
		encounteredError := true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			ctx.SetRequest(r)
			next(ctx)
		}

		middleware.CheckJWT(handler).ServeHTTP(ctx.Response(), ctx.Request())

		if encounteredError {
			ctx.JSON(
				http.StatusUnauthorized,
				map[string]string{"message": "JWT is invalid."},
			)
		}
		return nil
	}
}
