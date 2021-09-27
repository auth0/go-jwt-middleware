package main

import (
	"fmt"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/golang-jwt/jwt/v4"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user")
	fmt.Fprintf(w, "This is an authenticated request")
	fmt.Fprintf(w, "Claim content:\n")
	for k, v := range user.(*jwt.Token).Claims.(jwt.MapClaims) {
		fmt.Fprintf(w, "%s :\t%#v\n", k, v)
	}
})

func main() {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte("My Secret"), nil
		},
		// When set, the middleware verifies that tokens are signed with the specific signing algorithm
		// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
		// Important to avoid security issues described here: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
		SigningMethod: jwt.SigningMethodHS256,
	})

	app := jwtMiddleware.Handler(myHandler)
	http.ListenAndServe("0.0.0.0:3000", app)
}
