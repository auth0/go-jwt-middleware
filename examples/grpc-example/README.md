# gRPC Example

This is an example of how to build an endpoint middleware for a gRPC application.

## Background

The implementation of `jwtmiddleware.CheckJWT` is such that it is only to be used on HTTP endpoints. For an application
that leverages an HTTP <-> gRPC gateway, deeper methods need to be used. 

## How to use this middleware?

This example is not runnable, by default. The provided middleware is an example of how you could implement the 
`jwtmiddleware.CheckJWT` functionality in a different format. The token validation is provided by the `TokenValidator` 
middleware.
