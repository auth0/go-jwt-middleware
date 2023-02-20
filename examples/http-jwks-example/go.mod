module example.com/http-jwks

go 1.19

require (
	github.com/auth0/go-jwt-middleware/v2 v2.1.0
	gopkg.in/square/go-jose.v2 v2.6.0
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require golang.org/x/crypto v0.4.0 // indirect
