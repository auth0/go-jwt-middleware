package main

import (
	"context"
	"github.com/kataras/iris/v12"
	"log"
	"net/http"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
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

	// We want this struct to be filled in with
	// our custom claims from the token.
	customClaims = func() validator.CustomClaims {
		return &CustomClaims{}
	}
)

// checkJWT is an iris.Handler middleware
// that will check the validity of our JWT.
func checkJWT() iris.Handler {
	// Set up the validator.
	jwtValidator, err := validator.New(
		keyFunc,
		validator.HS256,
		[]string{issuer},
		audience,
		validator.WithCustomClaims(customClaims),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Encountered error while validating JWT: %v", err)
	}

	middleware := jwtmiddleware.New(
		jwtValidator.ValidateToken,
		jwtmiddleware.WithErrorHandler(errorHandler),
	)

	return func(ctx iris.Context) {
		encounteredError := true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			ctx.ResetRequest(r)
			ctx.Next()
		}

		middleware.CheckJWT(handler).ServeHTTP(ctx.ResponseWriter(), ctx.Request())

		if encounteredError {
			ctx.StopWithJSON(
				iris.StatusUnauthorized,
				map[string]string{"message": "JWT is invalid."},
			)
		}
	}
}
