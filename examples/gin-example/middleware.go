package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gin-gonic/gin"
)

var (
	// The signing key for the token.
	signingKey = []byte("abcdefghijklmnopqrstuvwxyz012345")

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
		return &CustomClaimsExample{}
	}
)

// checkJWT is a gin.HandlerFunc middleware
// that will check the validity of our JWT.
func checkJWT() gin.HandlerFunc {
	// Set up the validator.
	jwtValidator, err := validator.New(
		keyFunc,
		validator.HS256,
		issuer,
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

	return func(ctx *gin.Context) {
		encounteredError := true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			ctx.Request = r
			ctx.Next()
		}

		middleware.CheckJWT(handler).ServeHTTP(ctx.Writer, ctx.Request)

		if encounteredError {
			ctx.AbortWithStatusJSON(
				http.StatusUnauthorized,
				map[string]string{"message": "JWT is invalid."},
			)
		}
	}
}
