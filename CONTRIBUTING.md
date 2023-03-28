# Contributing

We appreciate feedback and contribution to this repo. Before you get started, please see [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md).


Before you submit a pull request, there are a couple requirements to satisfy.

## Linting and formatting code

This project uses [golangci-lint](https://github.com/golangci/golangci-lint) to enforce coding standards. It can be ran locally using `make lint`, this will also fix any autofixable errors within the code.

## Running the tests

Tests can be ran using `make test`. To run a specific test pass the `FILTER` var, for example `make test FILTER="Test_invalidError"`.

## Running the examples

This repo contains some examples of integrating the middleware with the Go builtin `net/http` and a custom middleware for [Gin](https://gin-gonic.com/).

To run these examples:

* `cd` into the directory of the example
* Install dependencies using `go mod vendor`
* Run the sample using `run main.go`

Each folder also contains a `README.md` file that details any specifics on how to run the example.