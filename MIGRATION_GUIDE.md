# Migration Guide

## Upgrading from v1.x → v2.0

Our version 2 release includes many significant improvements:

- Customizable JWT validation. 
- Full support for custom claims.
- Full support for custom error handlers.
- Added support for retrieving the JWKS from the Issuer.

As is to be expected with a major release, there are breaking changes in this update. Please ensure you read this guide
thoroughly and prepare your API before upgrading to SDK v2.

### Breaking Changes

- [jwtmiddleware.Options](#jwtmiddlewareoptions)
  - [ValidationKeyGetter](#validationkeygetter)
  - [UserProperty](#userproperty)
  - [ErrorHandler](#errorhandler)
  - [CredentialsOptional](#credentialsoptional)
  - [Extractor](#extractor)
  - [Debug](#debug)
  - [EnableAuthOnOptions](#enableauthonoptions)
  - [SigningMethod](#signingmethod)
- [jwtmiddleware.New](#jwtmiddlewarenew)
- [jwtmiddleware.Handler](#jwtmiddlewarehandler)
- [jwtmiddleware.CheckJWT](#jwtmiddlewarecheckjwt)

#### `jwtmiddleware.Options`

Now handled by individual [jwtmiddleware.Option](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#Option) items. 
They can be passed to [jwtmiddleware.New](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#New) after the 
[jwtmiddleware.ValidateToken](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#ValidateToken) input:

```golang
jwtmiddleware.New(validator, WithCredentialsOptional(true), ...)
```

##### `ValidationKeyGetter`

Token validation is now handled via a token provider which can be learned about in the section on 
[jwtmiddleware.New](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#New).

##### `UserProperty`

This is now handled in the validation provider.

##### `ErrorHandler`

We now provide a public [jwtmiddleware.ErrorHandler](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#ErrorHandler)
type:

```golang
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
```

A [default](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#DefaultErrorHandler) is provided which translates
errors into appropriate HTTP status codes.

You might want to wrap the default, so you can hook things into, like logging:

```golang
myErrHandler := func(w http.ResponseWriter, r *http.Request, err error) {
	fmt.Printf("error in token validation: %+v\n", err)

	jwtmiddleware.DefaultErrorHandler(w, r, err)
}

jwtMiddleware := jwtmiddleware.New(validator.ValidateToken, jwtmiddleware.WithErrorHandler(myErrHandler))
```

##### `CredentialsOptional`

Use the option function 
[jwtmiddleware.WithCredentialsOptional(true|false)](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#WithCredentialsOptional).
Default is false.

##### `Extractor`

Use the option function [jwtmiddleware.WithTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#WithTokenExtractor).
Default is to extract tokens from the auth header.

We provide 3 different token extractors:
- [jwtmiddleware.AuthHeaderTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#AuthHeaderTokenExtractor) renamed from `jwtmiddleware.FromAuthHeader`.
- [jwtmiddleware.CookieTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#CookieTokenExtractor) a new extractor.
- [jwtmiddleware.ParameterTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#ParameterTokenExtractor) renamed from `jwtmiddleware.FromParameter`.

And also an extractor which can combine multiple different extractors together: 
[jwtmiddleware.MultiTokenExtractor](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#MultiTokenExtractor) renamed from `jwtmiddleware.FromFirst`.

##### `Debug`

Removed. Please review individual exception messages for error details.

##### `EnableAuthOnOptions`

Use the option function [jwtmiddleware.WithValidateOnOptions(true|false)](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#WithValidateOnOptions). Default is true.

##### `SigningMethod`

This is now handled in the validation provider.

#### `jwtmiddleware.New`

A token provider is set up in the middleware by passing a 
[jwtmiddleware.ValidateToken](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#ValidateToken)
function:

```golang
func(context.Context, string) (interface{}, error)
```

to [jwtmiddleware.New](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#New).

In the example above you can see 
[github.com/auth0/go-jwt-middleware/validator](https://pkg.go.dev/github.com/auth0/go-jwt-middleware@v2.0.0/validator)
being used.

This change was made to allow the JWT validation provider to be easily switched out.

Options are passed into `jwtmiddleware.New` after validation provider and use the `jwtmiddleware.With...` functions to 
set options.

#### `jwtmiddleware.Handler*`

Both `jwtmiddleware.HandlerWithNext` and `jwtmiddleware.Handler` have been dropped.
You can use [jwtmiddleware.CheckJWT](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#JWTMiddleware.CheckJWT) 
instead which takes in an `http.Handler` and returns an `http.Handler`.

#### `jwtmiddleware.CheckJWT`

This function has been reworked to be the main middleware handler piece, and so we've dropped the functionality of it 
returning and error.

If you need to handle any errors please use the
[jwtmiddleware.WithErrorHandler](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#WithErrorHandler) function.
