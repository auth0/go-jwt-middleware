module github.com/auth0/go-jwt-middleware/examples

go 1.17

require (
	github.com/auth0/go-jwt-middleware v0.0.0
	gopkg.in/square/go-jose.v2 v2.5.1
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20211117183948-ae814b36b871 // indirect
)

replace github.com/auth0/go-jwt-middleware => ./../
