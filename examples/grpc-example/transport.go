package main

import "github.com/go-kit/kit/transport/grpc"

type GrpcTransport struct {
	doTheThing grpc.Handler
}

func NewGrpcTransport(ep *ExampleEndpoints) *GrpcTransport {
	return &GrpcTransport{
		doTheThing: grpc.NewServer(
			ep.DoTheThing,
			nil,
			nil,
		),
	}
}
