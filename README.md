# GO JWT Middleware

A middleware that will check that a [JWT](http://jwt.io/) is sent on the `Authorization` header and will then set the content of the JWT into the `user` variable of the request.

This module lets you authenticate HTTP requests using JWT tokens in your Go Programming Language applications. JWTs are typically used to protect API endpoints, and are often issued using OpenID Connect.

## Key Features

* Ability to **check the `Authorization` header for a JWT**
* **Decode the JWT** and set the content of it to the request context

## Installing

````bash
go get github.com/auth0/go-jwt-middleware
````

## Using it

You can use `jwtmiddleware` with default `net/http` as follows.

````go
// main.go
package main

import (
    "net/http"
    "github.com/auth0/go-jwt-middleware"
    "github.com/gorilla/context"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user := context.Get(r, "user")
    w.Write([]byte("hello world. This is an authenticated request"))
})

func main() {
    jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
      ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
        return []byte("My Secret Key"), nil
      },
    })

    app := jwtMiddleware.Handler(myHandler)
    http.ListenAndServe("0.0.0.0:3000", app)
}
````

You can also use it with Negroni as follows:

````go
// main.go
package main

import (
    "net/http"
    "github.com/auth0/go-jwt-middleware"
    "github.com/gorilla/context"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user := context.Get(r, "user")
    w.Write([]byte("hello world. This is an authenticated request"))
})

func main() {
    r := mux.NewRouter()

    jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
      ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
        decoded, err := base64.URLEncoding.DecodeString(os.Getenv("AUTH0_CLIENT_SECRET"))
        if err != nil {
          return nil, err
        }
        return decoded, nil
      },
    })

    r.HandleFunc("/ping", PingHandler)
    r.Handle("/secured/ping", negroni.New(
      negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
      negroni.Wrap(http.HandlerFunc(myHandler)),
    ))
    http.Handle("/", r)
    http.ListenAndServe(":3001", nil)
}
````

## Options

````go
type Options struct {
  // The function that will return the Key to validate the JWT. 
  // It can be either a shared secret or a public key.
  // Default value: nil
  ValidationKeyGetter jwt.Keyfunc
  // The name of the property in the request where the user information 
  // from the JWT will be stored.
  // Default value: "user"
  UserProperty string
  // The function that will be called when there's an error validating the token
  // Default value: https://github.com/auth0/go-jwt-middleware/blob/master/jwtmiddleware.go#L35
  ErrorHandler errorHandler
  // A boolean indicating if the credentials are required or not
  // Default value: false
  CredentialsOptional bool
}
````

## Examples

You can check out working examples in the [examples folder](https://github.com/auth0/go-jwt-middleware/tree/master/examples)

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## License

MIT

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.