module github.com/auth0/go-jwt-middleware/examples

go 1.14

require (
	github.com/auth0/go-jwt-middleware v0.0.0
	github.com/codegangsta/inject v0.0.0-20150114235600-33e0aa1cb7c0 // indirect
	github.com/go-martini/martini v0.0.0-20170121215854-22fa46961aab
	github.com/golang-jwt/jwt/v4 v4.1.0
	github.com/gorilla/mux v1.7.4
	github.com/urfave/negroni v1.0.0
)

replace github.com/auth0/go-jwt-middleware => ../
