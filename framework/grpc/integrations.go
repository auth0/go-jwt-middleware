package grpcjwt

import (
	"context"
	"time"
)

// Logger defines an interface for logging JWT operations.
type Logger interface {
	// Debug logs debug level messages
	Debug(msg string, keyvals ...interface{})
	// Info logs info level messages
	Info(msg string, keyvals ...interface{})
	// Error logs error level messages
	Error(msg string, keyvals ...interface{})
}

// MetricsRecorder defines an interface for recording metrics about JWT operations.
type MetricsRecorder interface {
	// IncAuthSuccess increments a counter for successful authentications
	IncAuthSuccess(method string)
	// IncAuthFailure increments a counter for failed authentications
	IncAuthFailure(method string, reason string)
	// ObserveAuthLatency records the latency of the authentication process
	ObserveAuthLatency(method string, duration time.Duration)
}

// Tracer defines an interface for tracing JWT operations.
type Tracer interface {
	// StartSpan starts a new span for JWT operations
	StartSpan(ctx context.Context, method string) (context.Context, interface{})
	// FinishSpan finishes a span
	FinishSpan(span interface{}, err error)
	// AddAttribute adds an attribute to a span
	AddAttribute(span interface{}, key, value string)
}

// NoopLogger is a Logger implementation that does nothing.
type NoopLogger struct{}

func (l *NoopLogger) Debug(msg string, keyvals ...interface{}) {}
func (l *NoopLogger) Info(msg string, keyvals ...interface{})  {}
func (l *NoopLogger) Error(msg string, keyvals ...interface{}) {}

// NoopMetricsRecorder is a MetricsRecorder implementation that does nothing.
type NoopMetricsRecorder struct{}

func (m *NoopMetricsRecorder) IncAuthSuccess(method string)                             {}
func (m *NoopMetricsRecorder) IncAuthFailure(method string, reason string)              {}
func (m *NoopMetricsRecorder) ObserveAuthLatency(method string, duration time.Duration) {}

// NoopTracer is a Tracer implementation that does nothing.
type NoopTracer struct{}

func (t *NoopTracer) StartSpan(ctx context.Context, method string) (context.Context, interface{}) {
	return ctx, nil
}
func (t *NoopTracer) FinishSpan(span interface{}, err error)           {}
func (t *NoopTracer) AddAttribute(span interface{}, key, value string) {}

// WithLogger sets the logger for the interceptor.
func WithLogger(logger Logger) Option {
	return func(i *JWTInterceptor) {
		i.logger = logger
	}
}

// WithMetricsRecorder sets the metrics recorder for the interceptor.
func WithMetricsRecorder(recorder MetricsRecorder) Option {
	return func(i *JWTInterceptor) {
		i.metricsRecorder = recorder
	}
}

// WithTracer sets the tracer for the interceptor.
func WithTracer(tracer Tracer) Option {
	return func(i *JWTInterceptor) {
		i.tracer = tracer
	}
}
