module example.com/http

go 1.21

require github.com/auth0/go-jwt-middleware/v2 v2.2.1

replace github.com/auth0/go-jwt-middleware/v2 => ./../../

require golang.org/x/crypto v0.24.0 // indirect
