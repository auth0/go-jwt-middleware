package jwtmiddleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestNoopTracer(t *testing.T) {
	tracer := &NoopTracer{}
	span := tracer.StartSpan("test_span", "tag1", "value1", "tag2", "value2")

	// Verify type
	_, ok := span.(*NoopSpan)
	assert.True(t, ok, "Should return a NoopSpan")

	// Test span methods - these should not panic
	span.Finish()
	span.SetTag("tag", "value")
	span.LogFields("field1", "value1", "field2", "value2")
}

func TestOpenTelemetryTracer(t *testing.T) {
	// Create a no-op tracer provider for testing
	tp := noop.NewTracerProvider()
	noopTracer := tp.Tracer("test")

	// Create our wrapper tracer
	tracer := NewOpenTelemetryTracer(noopTracer)

	// Test StartSpan
	span := tracer.StartSpan("test_span", "tag1", "value1", "tag2", "value2")

	// Verify type
	_, ok := span.(*OpenTelemetrySpan)
	assert.True(t, ok, "Should return an OpenTelemetrySpan")

	// Test span methods - these should not panic
	span.Finish()
	span.SetTag("tag", "value")
	span.LogFields("field1", "value1", "field2", "value2")
}
