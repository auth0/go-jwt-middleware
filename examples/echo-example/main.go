package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	jwtechohandler "github.com/auth0/go-jwt-middleware/v2/framework/echo" // Import the Echo integration
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/labstack/echo/v4"
)

// Try it out with:
//
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.XFhrzWzntyINkgoRt2mb8dES84dJcuOoORdzKfwUX70
//
// which is signed with 'secret' and has the data:
//
//	{
//	  "iss": "go-jwt-middleware-example",
//	  "aud": "audience-example",
//	  "sub": "1234567890",
//	  "name": "John Doe",
//	  "iat": 1516239022,
//	  "username": "user123"
//	}
//
// You can also try out the custom validation with:
//
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyIsInNob3VsZFJlamVjdCI6dHJ1ZX0.Jf13PY_Oyu2x3Gx1JQ0jXRiWaCOb5T2RbKOrTPBNHJA
//
// which is signed with 'secret' and has the data:
//
//	{
//	  "iss": "go-jwt-middleware-example",
//	  "aud": "audience-example",
//	  "sub": "1234567890",
//	  "name": "John Doe",
//	  "iat": 1516239022,
//	  "username": "user123",
//	  "shouldReject": true
//	}

var (
	// Configuration
	issuer       = "go-jwt-middleware-example"
	audience     = []string{"audience-example"}
	signingKey   = []byte("secret")
	customClaims = func() validator.CustomClaims {
		return &CustomClaimsExample{}
	}
	keyfunc = func(ctx context.Context) (any, error) {
		return signingKey, nil
	}
)

// CustomClaimsExample contains custom data we want from the token.
type CustomClaimsExample struct {
	Name         string `json:"name"`
	Username     string `json:"username"`
	ShouldReject bool   `json:"shouldReject,omitempty"`
}

// Validate errors out if `ShouldReject` is true.
func (c *CustomClaimsExample) Validate(ctx context.Context) error {
	if c.ShouldReject {
		return errors.New("should reject was set to true")
	}
	return nil
}

func main() {
	app := echo.New()

	// Set up the validator.
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyfunc),
		validator.WithSignatureAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience...),
		validator.WithCustomClaims(customClaims),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Create and apply the middleware
	echoMiddleware := jwtechohandler.New(jwtValidator.ValidateToken, []jwtmiddleware.Option{})

	// Apply the middleware to specific routes or use it as a global middleware
	app.GET("/", func(ctx echo.Context) error {
		claims, err := jwtechohandler.GetClaims(ctx)
		if err != nil {
			ctx.JSON(
				http.StatusInternalServerError,
				map[string]string{"message": "Failed to get validated JWT claims."},
			)
			return nil
		}

		customClaims, ok := claims.CustomClaims.(*CustomClaimsExample)
		if !ok {
			ctx.JSON(
				http.StatusInternalServerError,
				map[string]string{"message": "Failed to cast custom JWT claims to specific type."},
			)
			return nil
		}

		if len(customClaims.Username) == 0 {
			ctx.JSON(
				http.StatusBadRequest,
				map[string]string{"message": "Username in JWT claims was empty."},
			)
			return nil
		}

		ctx.JSON(http.StatusOK, claims)
		return nil
	}, echoMiddleware)

	log.Print("Server listening on http://localhost:3000")
	if err := app.Start(":3000"); err != nil {
		log.Fatalf("There was an error with the http server: %v", err)
	}
}
