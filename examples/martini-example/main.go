package main

import (
	"encoding/json"
	"log"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/go-martini/martini"
	"github.com/lestrrat-go/jwx/jwa"
)

func main() {

	StartServer()

}

func StartServer() {
	m := martini.Classic()

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		Key:           "your-256-bit-secret",
		SigningMethod: jwa.HS256,
	})

	m.Get("/ping", PingHandler)
	m.Get("/secured/ping", jwtMiddleware.CheckJWT, SecuredPingHandler)

	m.Run()
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
	// TODO(jayhelton) the martini example doesnt seem to pass along the middleware on this branch, it receives and <invalid Value> message and skips the handler
	tokenStr := r.Context().Value("user")
	log.Println(tokenStr)
	respondJSON("All good. You only get this message if you're authenticated", w)
}
