package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"

	"github.com/auth0/go-jwt-middleware"
	"github.com/auth0/go-jwt-middleware/validate/jwt-go"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*CustomClaimsExample)

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

// CustomClaimsExample contains custom data we want from the token.
type CustomClaimsExample struct {
	Username     string `json:"username"`
	ShouldReject bool   `json:"shouldReject,omitempty"`
	jwt.RegisteredClaims
}

// Validate does nothing for this example, however we can
// validate in here any expectations we have on our claims.
func (c *CustomClaimsExample) Validate(ctx context.Context) error {
	if c.ShouldReject {
		return errors.New("should reject was set to true")
	}
	return nil
}

func main() {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		// Our token must be signed using this data.
		return []byte("secret"), nil
	}

	customClaims := func() jwtgo.CustomClaims {
		// We want this struct to be filled in with
		// our custom claims from the token.
		return &CustomClaimsExample{}
	}

	// Set up the jwt-go validator.
	validator, err := jwtgo.New(
		keyFunc,
		"HS256",
		jwtgo.WithCustomClaims(customClaims),
	)
	if err != nil {
		log.Fatalf("failed to set up the jwt-go validator: %v", err)
	}

	// Set up the middleware.
	middleware := jwtmiddleware.New(validator.ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", middleware.CheckJWT(handler))
	// Try it out with:
	//
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqd3Rnby1leGFtcGxlIiwic3ViIjoiMTIzNDU2Nzg5MCIsImlhdCI6MTUxNjIzOTAyMiwidXNlcm5hbWUiOiJ1c2VyMTIzIn0.ha_JgA29vSAb3HboPRXEi9Dm5zy7ARzd4P8AFoYP9t0
	//
	// which is signed with 'secret' and has the data:
	// {
	//   "iss": "jwtgo-example",
	//   "sub": "1234567890",
	//   "iat": 1516239022,
	//   "username": "user123"
	// }
	//
	// You can also try out the custom validation with:
	//
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqd3Rnby1leGFtcGxlIiwic3ViIjoiMTIzNDU2Nzg5MCIsImlhdCI6MTUxNjIzOTAyMiwidXNlcm5hbWUiOiJ1c2VyMTIzIiwic2hvdWxkUmVqZWN0Ijp0cnVlfQ.awZ0DFpJ-hH5xn-q-sZHJWj7oTAOkPULwgFO4O6D67o
	//
	// which is signed with 'secret' and has the data:
	// {
	//	 "iss": "jwtgo-example",
	//	 "sub": "1234567890",
	//	 "iat": 1516239022,
	//	 "username": "user123",
	//	 "shouldReject": true
	// }
}
