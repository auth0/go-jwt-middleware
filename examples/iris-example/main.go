package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	jwtiris "github.com/auth0/go-jwt-middleware/v2/framework/iris"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/kataras/iris/v12"
	"go.uber.org/zap"
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

// Configuration variables
var (
	// The signing key for the token.
	signingKey = []byte("secret")

	// The issuer of our token.
	issuer = "go-jwt-middleware-example"

	// The audience of our token.
	audience = []string{"audience-example"}
)

// CustomClaims contains custom data we want from the token.
type CustomClaims struct {
	Name         string `json:"name"`
	Username     string `json:"username"`
	ShouldReject bool   `json:"shouldReject,omitempty"`
}

// Validate errors out if any custom claims are invalid
func (c *CustomClaims) Validate(ctx context.Context) error {
	if c.ShouldReject {
		return errors.New("should reject was set to true")
	}
	return nil
}

func main() {
	app := iris.New()

	// Configuration
	keyFunc := func(ctx context.Context) (interface{}, error) {
		return signingKey, nil
	}

	// Set up the validator.
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyFunc),
		validator.WithSignatureAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience...),
		validator.WithCustomClaims(func() validator.CustomClaims {
			return &CustomClaims{}
		}),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to set up the JWT validator: %v", err)
	}

	// Set up zap logger and use it with the middleware
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel) // Set zap to debug level
	zapLogger, _ := cfg.Build()
	sugar := zapLogger.Sugar()
	logger := jwtmiddleware.NewZapLogger(sugar)

	// Create and apply the Iris middleware
	irisMiddleware := jwtiris.New(
		jwtValidator.ValidateToken,
		[]jwtmiddleware.Option{
			jwtmiddleware.WithLogger(logger, jwtmiddleware.LogLevelDebug),
		},
	)

	// Apply the middleware to a route
	app.Get("/", irisMiddleware, func(ctx iris.Context) {
		// Get claims using the helper function from the framework adapter
		claims, err := jwtiris.GetClaims(ctx)
		if err != nil {
			ctx.StopWithJSON(
				http.StatusInternalServerError,
				map[string]string{"message": "Failed to get validated JWT claims."},
			)
			return
		}

		customClaims, ok := claims.CustomClaims.(*CustomClaims)
		if !ok {
			ctx.StopWithJSON(
				http.StatusInternalServerError,
				map[string]string{"message": "Failed to cast custom JWT claims to specific type."},
			)
			return
		}

		if len(customClaims.Username) == 0 {
			ctx.StopWithJSON(
				http.StatusBadRequest,
				map[string]string{"message": "Username in JWT claims was empty."},
			)
			return
		}

		ctx.JSON(claims)
	})

	log.Print("Server listening on http://localhost:3000")
	if err := app.Listen(":3000"); err != nil {
		log.Fatalf("There was an error with the http server: %v", err)
	}
}
