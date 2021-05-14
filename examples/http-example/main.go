package main

import (
	"context"
	"fmt"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
)

// TODO: replace this with default validate token func once it is merged in
func REPLACE_ValidateToken(_ context.Context, token string) (interface{}, error) {
	// Now parse the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte("My Secret"), nil
	})

	// Check if there was an error in parsing...
	if err != nil {
		return nil, err
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		return nil, jwtmiddleware.ErrJWTInvalid
	}

	return parsedToken, nil
}

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user")
	fmt.Fprintf(w, "This is an authenticated request")
	fmt.Fprintf(w, "Claim content:\n")
	for k, v := range user.(*jwt.Token).Claims.(jwt.MapClaims) {
		fmt.Fprintf(w, "%s :\t%#v\n", k, v)
	}
})

func main() {
	jwtMiddleware := jwtmiddleware.New(REPLACE_ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", jwtMiddleware.CheckJWT(myHandler))
}
