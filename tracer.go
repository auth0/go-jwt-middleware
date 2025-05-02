package jwtmiddleware

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Tracer is a generic tracing interface for the middleware.
type Tracer interface {
	StartSpan(operationName string, opts ...interface{}) Span
}

type Span interface {
	Finish()
	SetTag(key string, value interface{})
	LogFields(fields ...interface{})
}

// NoopTracer is a default tracer that does nothing.
type NoopTracer struct{}

func (t *NoopTracer) StartSpan(operationName string, opts ...interface{}) Span {
	return &NoopSpan{}
}

type NoopSpan struct{}

func (s *NoopSpan) Finish()                              {}
func (s *NoopSpan) SetTag(key string, value interface{}) {}
func (s *NoopSpan) LogFields(fields ...interface{})      {}

// OpenTelemetryTracer implements the Tracer interface using OpenTelemetry.
type OpenTelemetryTracer struct {
	tracer oteltrace.Tracer
}

func NewOpenTelemetryTracer(tracer oteltrace.Tracer) Tracer {
	return &OpenTelemetryTracer{tracer: tracer}
}

func (t *OpenTelemetryTracer) StartSpan(operationName string, opts ...interface{}) Span {
	ctx := context.Background()
	var span oteltrace.Span
	_, span = t.tracer.Start(ctx, operationName)
	return &OpenTelemetrySpan{span: span}
}

// OpenTelemetrySpan implements the Span interface using OpenTelemetry.
type OpenTelemetrySpan struct {
	span oteltrace.Span
}

func (s *OpenTelemetrySpan) Finish() {
	s.span.End()
}

func (s *OpenTelemetrySpan) SetTag(key string, value interface{}) {
	s.span.SetAttributes(attribute.String(key, fmt.Sprint(value)))
}

func (s *OpenTelemetrySpan) LogFields(fields ...interface{}) {}
