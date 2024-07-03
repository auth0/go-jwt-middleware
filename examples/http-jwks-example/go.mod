module example.com/http-jwks

go 1.22.3

toolchain go1.22.4

require (
	github.com/auth0/go-jwt-middleware/v2 v2.1.0
	gopkg.in/go-jose/go-jose.v2 v2.6.3
)

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require (
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
)
