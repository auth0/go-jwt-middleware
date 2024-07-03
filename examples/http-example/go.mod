module example.com/http

go 1.23.0

require (
	github.com/auth0/go-jwt-middleware/v2 v2.2.2
	github.com/go-jose/go-jose/v4 v4.0.4
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require golang.org/x/crypto v0.35.0 // indirect
