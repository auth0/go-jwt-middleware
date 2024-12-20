# GRPC example

This is an example of how to use the grpc middleware.

# Using it

To try this out:

* Install all dependencies with `go mod vendor`.
* Run `go run main.go` to start the app.
* Use [jwt.io](https://jwt.io/) to generate a JWT signed with the HS256 algorithm and `abcdefghijklmnopqrstuvwxyz012345`.
* [optional] use [grpc-client-cli](https://github.com/vadimi/grpc-client-cli) and run `echo '{"msg":"hello"}' | grpc-client-cli --insecure --proto=example.proto --header "authorization: <jwt from jwt.io>" --service ExampleService --method DoSomething localhost:8080
`
