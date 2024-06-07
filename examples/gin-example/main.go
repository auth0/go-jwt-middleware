package main

import (
	"log"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gin-gonic/gin"
)

// Try it out with:
//
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyJ9.efMBnTwQly3QNK8RxZeI8nscQVKMEtVqZUXC9MA6JsQ
//
// which is signed with 'your-256-bit-secret-is-just-enough' and has the data:
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
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiYXVkaWVuY2UtZXhhbXBsZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsInVzZXJuYW1lIjoidXNlcjEyMyIsInNob3VsZFJlamVjdCI6dHJ1ZX0.oWqSLPLRzF2upnnIUls0rE8rANy_IaC0qrV-jjOm89M
//
// which is signed with 'your-256-bit-secret-is-just-enough' and has the data:
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

func main() {
	router := gin.Default()
	router.GET("/", checkJWT(), func(ctx *gin.Context) {
		claims, ok := ctx.Request.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
		if !ok {
			ctx.AbortWithStatusJSON(
				http.StatusInternalServerError,
				map[string]string{"message": "Failed to get validated JWT claims."},
			)
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
		log.Fatalf("There was an error with the http server: %v", err)
	}
}
