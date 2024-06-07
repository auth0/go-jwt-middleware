# Gin example

This is an example of how to use the middleware with the [gin web framework](https://github.com/gin-gonic/gin).

# Using it

To try this out:

* Install all dependencies with `go mod vendor`.
*  Run `go run .` to start the app.
* Use [jwt.io](https://jwt.io/) to generate a JWT signed with the HS256 algorithm and `your-256-bit-secret-is-just-enough`.
* Call `http://localhost:3000` with the JWT to get a response back.
