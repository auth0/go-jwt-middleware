# GO JWT Middleware

[![GoDoc](https://pkg.go.dev/badge/github.com/auth0/go-jwt-middleware.svg)](https://pkg.go.dev/github.com/auth0/go-jwt-middleware)
[![License](https://img.shields.io/github/license/auth0/go-jwt-middleware.svg)](https://github.com/auth0/go-jwt-middleware/blob/master/LICENSE)
[![Release](https://img.shields.io/github/v/release/auth0/go-jwt-middleware)](https://github.com/auth0/go-jwt-middleware/releases/latest)
[![Codecov](https://codecov.io/gh/auth0/go-jwt-middleware/branch/master/graph/badge.svg?token=fs2WrOXe9H)](https://codecov.io/gh/auth0/go-jwt-middleware)
[![Tests](https://github.com/auth0/go-jwt-middleware/actions/workflows/test.yaml/badge.svg)](https://github.com/auth0/go-jwt-middleware/actions/workflows/test.yaml?query=branch%3Amaster)
[![Stars](https://img.shields.io/github/stars/auth0/go-jwt-middleware.svg)](https://github.com/auth0/go-jwt-middleware/stargazers)
[![Contributors](https://img.shields.io/github/contributors/auth0/go-jwt-middleware)](https://github.com/auth0/go-jwt-middleware/graphs/contributors)

Golang middleware to check and validate [JWTs](jwt.io) in the request and add the valid token contents to the request 
context.

-------------------------------------

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Migration Guide](#migration-guide)
- [Issue Reporting](#issue-reporting)
- [Author](#author)
- [License](#license)

-------------------------------------

## Installation

```shell
go get github.com/auth0/go-jwt-middleware
```

[[table of contents]](#table-of-contents)

## Usage

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/auth0/go-jwt-middleware"
	"github.com/auth0/go-jwt-middleware/validator"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
})

func main() {
	keyFunc := func(ctx context.Context) (interface{}, error) {
		// Our token must be signed using this data.
		return []byte("secret"), nil
	}

	// Set up the validator.
	jwtValidator, err := validator.New(
		keyFunc,
		validator.HS256,
		"https://<issuer-url>/",
		[]string{"<audience>"},
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	// Set up the middleware.
	middleware := jwtmiddleware.New(jwtValidator.ValidateToken)

	http.ListenAndServe("0.0.0.0:3000", middleware.CheckJWT(handler))
}
```

After running that code (`go run main.go`) you can then curl the http server from another terminal:

```
$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJnby1qd3QtbWlkZGxld2FyZS1leGFtcGxlIiwiYXVkIjoiZ28tand0LW1pZGRsZXdhcmUtZXhhbXBsZSJ9.xcnkyPYu_b3qm2yeYuEgr5R5M5t4pN9s04U1ya53-KM" localhost:3000
```

That should give you the following response:

```
{
  "CustomClaims": null,
  "RegisteredClaims": {
    "iss": "go-jwt-middleware-example",
    "aud": "go-jwt-middleware-example",
    "sub": "1234567890",
    "iat": 1516239022
  }
}
```

The JWT included in the Authorization header above is signed with `secret`.

To test how the response would look like with an invalid token:

```
$ curl -v -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.yiDw9IDNCa1WXCoDfPR_g356vSsHBEerqh9IvnD49QE" localhost:3000
```

That should give you the following response:

```
...
< HTTP/1.1 401 Unauthorized
< Content-Type: application/json
{"message":"JWT is invalid."}
...
```

[[table of contents]](#table-of-contents)

## Migration Guide

If you are moving from v1 to v2 please check our [migration guide](MIGRATION_GUIDE.md).

[[table of contents]](#table-of-contents)

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

[[table of contents]](#table-of-contents)

## Author

[Auth0](https://auth0.com/)

[[table of contents]](#table-of-contents)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

[[table of contents]](#table-of-contents)
