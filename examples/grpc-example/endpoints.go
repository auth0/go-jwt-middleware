package main

import (
	"context"
	"github.com/go-kit/kit/endpoint"
)

func makeDoTheThingEndpoint(s ExampleService) endpoint.Endpoint {
	return func(ctx context.Context, r interface{}) (interface{}, error) {
		req := r.(*example.DoTheThingRequest)
		return s.DoTheThing(ctx, req)
	}
}

type ExampleEndpoints struct {
	DoTheThing endpoint.Endpoint
}

func CreateEndoints(svc ExampleService) *ExampleEndpoints {
	doTheThingEndpoint := endpoint.Chain(
		TokenValidator(ExampleAuth0Issuer),
	)(makeDoTheThingEndpoint(svc))

	return &ExampleEndpoints{
		DoTheThing: doTheThingEndpoint,
	}
}
