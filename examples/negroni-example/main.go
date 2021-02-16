package main

import (
	"encoding/json"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/urfave/negroni"
)

func main() {

	StartServer()

}

func StartServer() {
	r := mux.NewRouter()

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		Key: "your-256-bit-secret",
		ValidatorFunc: func(parsedToken jwt.Token) bool {
			// Token validation is easy if you leverage jwx package, otherwise you can manually
			// check the contents of the token object
			// Todo(jayhelton) add manual parse exampls
			err := jwt.Validate(parsedToken, jwt.WithAudience("example.com"),
				jwt.WithIssuer("auth.example.com"),
				jwt.WithClaimValue("custom", "claim"))

			// Check if the parsed token is valid...
			if err != nil {
				return false
			}
			return true
		},
		SigningMethod: jwa.HS256,
	})

	r.HandleFunc("/ping", PingHandler)
	r.Handle("/secured/ping", negroni.New(
		negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(SecuredPingHandler)),
	))
	http.Handle("/", r)
	http.ListenAndServe(":3001", nil)
}

type Response struct {
	Text string `json:"text"`
}

func respondJSON(text string, w http.ResponseWriter) {
	response := Response{text}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON("All good. You don't need to be authenticated to call this", w)
}

func SecuredPingHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON("All good. You only get this message if you're authenticated", w)
}
