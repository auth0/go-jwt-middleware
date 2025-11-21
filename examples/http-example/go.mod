module example.com/http

go 1.24.0

toolchain go1.24.8

require (
	github.com/auth0/go-jwt-middleware/v3 v3.0.0
	gopkg.in/go-jose/go-jose.v2 v2.6.3
)

replace github.com/auth0/go-jwt-middleware/v3 => ./../../

require golang.org/x/crypto v0.45.0 // indirect
