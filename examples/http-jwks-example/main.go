package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/auth0/go-jwt-middleware"
	"github.com/auth0/go-jwt-middleware/validate/josev2"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(jwtmiddleware.ContextKey{})
	j, err := json.MarshalIndent(user, "", "\t")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
	}

	fmt.Fprintf(w, "This is an authenticated request\n")
	fmt.Fprintf(w, "Claim content:\n")
	fmt.Fprint(w, string(j))
})

func main() {
	u, err := url.Parse("https://<your tenant domain>")
	if err != nil {
		// we'll panic in order to fail fast
		panic(err)
	}

	p := josev2.NewCachingJWKSProvider(*u, 5*time.Minute)

	// setup the piece which will validate tokens
	validator, err := josev2.New(
		p.KeyFunc,
		jose.RS256,
	)
	if err != nil {
		// we'll panic in order to fail fast
		panic(err)
	}

	// setup the middleware
	m := jwtmiddleware.New(validator.ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", m.CheckJWT(handler))
}
