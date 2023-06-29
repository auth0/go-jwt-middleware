# Gin example

This is an example of how to use the middleware with the [echo web framework](https://github.com/labstack/echo).

# Using it

To try this out:

* Install all dependencies with `go mod vendor`.
* Run `go run main.go` to start the app.
* Use [jwt.io](https://jwt.io/) to generate a JWT signed with the HS256 algorithm and `secret`.
* Call `http://localhost:3000` with the JWT to get a response back.
