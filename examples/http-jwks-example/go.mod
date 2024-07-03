module example.com/http-jwks

go 1.23

require (
	github.com/auth0/go-jwt-middleware/v2 v2.1.0
	github.com/go-jose/go-jose/v4 v4.0.4
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require (
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
)
