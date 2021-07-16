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

## Migration Guide
If you are moving from v1 to v2 this is the place for you.

### `jwtmiddleware.Options`
Now handled by individual [jwtmiddleware.Option](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#Option) items. They can be passed to [jwtmiddleware.New](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#New) after the [jwtmiddleware.ValidateToken](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#ValidateToken) input:
```golang
jwtmiddleware.New(validator, WithCredentialsOptional(true), ...)
```

#### `ValidationKeyGetter`
Token validation is now handled via a token provider which can be learned about in the section on [jwtmiddleware.New](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#New).

#### `UserProperty`
This is now handled in the validation provider.

#### `ErrorHandler`
We now provide a public [jwtmiddleware.ErrorHandler](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#ErrorHandler) type:
```golang
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
```

A [default](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#DefaultErrorHandler) is provided which translates errors into HTTP status codes.

You might want to wrap the default so you can hook things into logging:
```golang
myErrHandler := func(w http.ResponseWriter, r *http.Request, err error) {
	fmt.Printf("error in token validation: %+v\n", err)

	jwtmiddleware.DefaultErrorHandler(w, r, err)
}

jwtMiddleware := jwtmiddleware.New(validator.ValidateToken, jwtmiddleware.WithErrorHandler(myErrHandler))
```

#### `CredentialsOptional`
Use the option function [jwtmiddleware.WithCredentialsOptional(true|false)](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#WithCredentialsOptional). Default is false.

#### `Extractor`
Use the option function [jwtmiddleware.WithTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#WithTokenExtractor). Default is to extract tokens from the auth header.

We provide 3 different token extractors:
- [jwtmiddleware.AuthHeaderTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#AuthHeaderTokenExtractor) a rename of `jwtmiddleware.FromAuthHeader`.
- [jwtmiddleware.CookieTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#CookieTokenExtractor) a new extractor.
- [jwtmiddleware.ParameterTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#ParameterTokenExtractor) a rename of `jwtmiddleware.FromParameter`.

And also an extractor which can combine multiple different extractors together: [jwtmiddleware.MultiTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#MultiTokenExtractor) a rename of `jwtmiddleware.FromFirst`.

#### `Debug`
Dropped. We don't believe that libraries should be logging so we have removed this option.
If you need more details of when things go wrong the errors should give the details you need.

#### `EnableAuthOnOptions`
Use the option function [jwtmiddleware.WithValidateOnOptions(true|false)](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#WithValidateOnOptions). Default is true.

#### `SigningMethod`
This is now handled in the validation provider.

### `jwtmiddleware.New`
A token provider is setup in the middleware by passing a [jwtmiddleware.ValidateToken](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#ValidateToken) function:
```golang
func(context.Context, string) (interface{}, error)
```
to [jwtmiddleware.New](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#New).

In the example above you can see [github.com/auth0/go-jwt-middleware/validate/josev2](https://pkg.go.dev/github.com/auth0/go-jwt-middleware@v2.0.0/validate/josev2) being used.

This change was made in order to allow JWT validation provider to be easily switched out.

Options are passed into `jwtmiddleware.New` after validation provider and use the `jwtmiddleware.With...` functions to set options.

### `jwtmiddleware.Handler*`
Both `jwtmiddleware.HandlerWithNext` and `jwtmiddleware.Handler` have been dropped.
You can use [jwtmiddleware.CheckJWT](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#CheckJWT) instead which takes in an `http.Handler` and returns an `http.Handler`.

### `jwtmiddleware.CheckJWT`
This function has been reworked to be the main middleware handler piece and so we've dropped the functionality of it returning and error.
If you need to handle any errors please use the [jwtmiddleware.WithErrorHandler](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#WithErrorHandler) function.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com/)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

[GoDoc]: https://pkg.go.dev/github.com/auth0/go-jwt-middleware
[GoDoc Widget]: https://pkg.go.dev/badge/github.com/auth0/go-jwt-middleware.svg
