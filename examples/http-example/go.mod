module example.com/http

go 1.19

require (
	github.com/auth0/go-jwt-middleware/v2 v2.1.0
	gopkg.in/go-jose/go-jose.v2 v2.6.3
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require golang.org/x/crypto v0.17.0 // indirect
