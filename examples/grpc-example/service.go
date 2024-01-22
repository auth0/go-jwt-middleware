package main

import "context"

type ExampleService interface {
	DoTheThing(ctx context.Context, req *example.DoTheThingRequest) (*example.DoTheThingResponse, error)
}
