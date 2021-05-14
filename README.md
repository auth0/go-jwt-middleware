# GO JWT Middleware

[![GoDoc Widget]][GoDoc]

**WARNING**
This `v2` branch is not production ready - use at your own risk.

Golang middleware to check and validate [JWTs](jwt.io) in the request and add the valid token contents to the request context.

## Installation
```
go get github.com/auth0/go-jwt-middleware
```

## Usage
```golang
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/auth0/go-jwt-middleware/validate/josev2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(jwtmiddleware.ContextKey{})
	j, err := json.MarshalIndent(user, "", "\t")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
	}

	fmt.Fprintf(w, "This is an authenticated request")
	fmt.Fprintf(w, "Claim content:\n")
	fmt.Fprint(w, string(j))
})

func main() {
	keyFunc := func(ctx context.Context) (interface{}, error) {
		// our token must be signed using this data
		return []byte("secret"), nil
	}

	expectedClaimsFunc := func() jwt.Expected {
		// By setting up expected claims we are saying a token must
		// have the data we specify.
		return jwt.Expected{
			Issuer: "josev2-example",
		}
	}

	// setup the piece which will validate tokens
	validator, err := josev2.New(
		keyFunc,
		jose.HS256,
		josev2.WithExpectedClaims(expectedClaimsFunc),
	)
	if err != nil {
		// we'll panic in order to fail fast
		panic(err)
	}

	// setup the middleware
	m := jwtmiddleware.New(validator.ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", m.CheckJWT(handler))
}
```

Running that code you can then curl it from another terminal:
```
$ curl -H Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJqb3NldjItZXhhbXBsZSJ9.e0lGglk9-m-n-t07eA5f7qgXGM-nD4ekwJkYVKprIUM" localhost:3000
```
should give you the response
```
This is an authenticated requestClaim content:
{
        "CustomClaims": null,
        "Claims": {
                "iss": "josev2-example",
                "sub": "1234567890",
                "iat": 1516239022
        }
}
```
The JWT included in the Authorization header above is signed with `secret`.

To test it not working:
```
$ curl -v -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.yiDw9IDNCa1WXCoDfPR_g356vSsHBEerqh9IvnD49QE" localhost:3000
```
should give you a response like
```
...
< HTTP/1.1 401 Unauthorized
...
```

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com/)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

[GoDoc]: https://pkg.go.dev/github.com/go-chi/chi?tab=versions
[GoDoc Widget]: https://godoc.org/github.com/auth0/go-jwt-middleware?status.svg
