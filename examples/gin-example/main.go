package main

import (
	"context"
	"errors"
	"log"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	jwtgin "github.com/auth0/go-jwt-middleware/v2/framework/gin"
	jwtginhandler "github.com/auth0/go-jwt-middleware/v2/framework/gin"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
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
	router := gin.Default()

	// Configuration
	issuer := "go-jwt-middleware-example"
	audience := []string{"audience-example"}
	signingKey := []byte("secret")
	keyfunc := func(ctx context.Context) (any, error) {
		return signingKey, nil
	}
	// Set up the validator.
	jwtValidator, err := validator.New(
		validator.WithKeyFunc(keyfunc),
		validator.WithSignatureAlgorithm(validator.HS256),
		validator.WithIssuer(issuer),
		validator.WithAudiences(audience...),
		validator.WithCustomClaims(func() validator.CustomClaims {
			return &CustomClaimsExample{}
		}),
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

	// Set up Prometheus metrics and OpenTelemetry tracer
	metrics := jwtmiddleware.NewPrometheusMetrics()
	tracer := jwtmiddleware.NewOpenTelemetryTracer(otel.Tracer("jwtmiddleware"))

	// Create and apply the Gin middleware
	customKey := "my_custom_key"
	ginMiddleware := jwtginhandler.New(
		jwtValidator.ValidateToken,
		[]jwtmiddleware.Option{
			jwtmiddleware.WithContextKey(customKey),
			jwtmiddleware.WithLogger(logger, jwtmiddleware.LogLevelDebug),
			jwtmiddleware.WithMetrics(metrics),
			jwtmiddleware.WithTracer(tracer),
		},
	)
	router.Use(ginMiddleware)
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	router.GET("/", func(ctx *gin.Context) {
		// In your handler
		claims, err := jwtgin.GetClaimsWithKey(ctx, customKey)
		if err != nil || claims == nil {
			ctx.AbortWithStatusJSON(401, gin.H{"message": "Failed to get validated JWT claims."})
			return
		}
		customClaims, ok := claims.CustomClaims.(*CustomClaimsExample)
		if !ok {
			ctx.AbortWithStatusJSON(
				http.StatusInternalServerError,
				map[string]string{"message": "Failed to cast custom JWT claims to specific type."},
			)
			return
		}

		if len(customClaims.Username) == 0 {
			ctx.AbortWithStatusJSON(
				http.StatusBadRequest,
				map[string]string{"message": "Username in JWT claims was empty."},
			)
			return
		}

		ctx.JSON(http.StatusOK, claims)
	})

	log.Print("Server listening on http://localhost:3000")
	if err := http.ListenAndServe("0.0.0.0:3000", router); err != nil {
		log.Fatalf("There was an error starting the server: %v", err)
	}
}
