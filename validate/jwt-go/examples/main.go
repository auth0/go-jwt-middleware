package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwtgo "github.com/auth0/go-jwt-middleware/validate/jwt-go"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

// CustomClaimsExample contains custom data we want from the token.
type CustomClaimsExample struct {
	Username     string `json:"username"`
	ShouldReject bool   `json:"shouldReject,omitempty"`
	jwt.StandardClaims
}

// Validate does nothing for this example
func (c *CustomClaimsExample) Validate(ctx context.Context) error {
	if c.ShouldReject {
		return errors.New("should reject was set to true")
	}
	return nil
}

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(jwtmiddleware.ContextKey{})
	j, err := json.MarshalIndent(claims, "", "\t")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
	}

	fmt.Fprintf(w, "This is an authenticated request\n")
	fmt.Fprintf(w, "Claim content: %s\n", string(j))
})

func main() {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		// our token must be signed using this data
		return []byte("secret"), nil
	}
	/*expectedClaims := func() jwt.Expected {
		// By setting up expected claims we are saying a token must
		// have the data we specify.
		return jwt.Expected{
			Issuer: "josev2-example",
			Time:   time.Now(),
		}
	}*/
	customClaims := func() jwtgo.CustomClaims {
		// we want this struct to be filled in with our custom claims
		// from the token
		return &CustomClaimsExample{}
	}

	// setup the jwt-go validator
	validator, err := jwtgo.New(
		keyFunc,
		"HS256",
		//jwtgo.WithExpectedClaims(expectedClaims),
		jwtgo.WithCustomClaims(customClaims),
		//jwtgo.WithAllowedClockSkew(30*time.Second),
	)

	if err != nil {
		// we'll panic in order to fail fast
		panic(err)
	}

	// setup the middleware
	m := jwtmiddleware.New(validator.ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", m.CheckJWT(handler))
	// try it out with eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqd3Rnby1leGFtcGxlIiwic3ViIjoiMTIzNDU2Nzg5MCIsImlhdCI6MTUxNjIzOTAyMiwidXNlcm5hbWUiOiJ1c2VyMTIzIn0.ha_JgA29vSAb3HboPRXEi9Dm5zy7ARzd4P8AFoYP9t0
	// which is signed with 'secret' and has the data:
	// {
	//   "iss": "jwtgo-example",
	//   "sub": "1234567890",
	//   "iat": 1516239022,
	//   "username": "user123"
	// }

	// you can also try out the custom validation with eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqd3Rnby1leGFtcGxlIiwic3ViIjoiMTIzNDU2Nzg5MCIsImlhdCI6MTUxNjIzOTAyMiwidXNlcm5hbWUiOiJ1c2VyMTIzIiwic2hvdWxkUmVqZWN0Ijp0cnVlfQ.awZ0DFpJ-hH5xn-q-sZHJWj7oTAOkPULwgFO4O6D67o
	// which is signed with 'secret' and has the data:
	// {
	//	 "iss": "jwtgo-example",
	//	 "sub": "1234567890",
	//	 "iat": 1516239022,
	//	 "username": "user123",
	//	 "shouldReject": true
	// }
}
