package grpcjwt

import (
	"context"
	"fmt"
	"log"
	"time"
)

// ------------------------------------------------
// Logging Adapters
// ------------------------------------------------

// StdLogger adapts Go's standard logger to the Logger interface.
type StdLogger struct {
	Log *log.Logger
}

func (l *StdLogger) Debug(msg string, keyvals ...interface{}) {
	l.Log.Printf("[DEBUG] %s %s", msg, formatKeyvals(keyvals...))
}

func (l *StdLogger) Info(msg string, keyvals ...interface{}) {
	l.Log.Printf("[INFO] %s %s", msg, formatKeyvals(keyvals...))
}

func (l *StdLogger) Error(msg string, keyvals ...interface{}) {
	l.Log.Printf("[ERROR] %s %s", msg, formatKeyvals(keyvals...))
}

// Helper function to format key-value pairs
func formatKeyvals(keyvals ...interface{}) string {
	// ... existing code ...
	if len(keyvals) == 0 {
		return ""
	}

	var result string
	for i := 0; i < len(keyvals); i += 2 {
		key := keyvals[i]
		var value interface{} = "missing"
		if i+1 < len(keyvals) {
			value = keyvals[i+1]
		}
		result += fmt.Sprintf("%v=%v ", key, value)
	}
	return result
}

// ZapAdapter adapts Zap logger to the Logger interface
type ZapAdapter struct {
	Logger interface{} // *zap.SugaredLogger
}

func (l *ZapAdapter) Debug(msg string, keyvals ...interface{}) {
	// When using the actual Zap library:
	// l.Logger.(*zap.SugaredLogger).Debugw(msg, keyvals...)
	fmt.Printf("[DEBUG] %s %s\n", msg, formatKeyvals(keyvals...))
}

func (l *ZapAdapter) Info(msg string, keyvals ...interface{}) {
	// When using the actual Zap library:
	// l.Logger.(*zap.SugaredLogger).Infow(msg, keyvals...)
	fmt.Printf("[INFO] %s %s\n", msg, formatKeyvals(keyvals...))
}

func (l *ZapAdapter) Error(msg string, keyvals ...interface{}) {
	// When using the actual Zap library:
	// l.Logger.(*zap.SugaredLogger).Errorw(msg, keyvals...)
	fmt.Printf("[ERROR] %s %s\n", msg, formatKeyvals(keyvals...))
}

// LogrusAdapter adapts Logrus to the Logger interface
type LogrusAdapter struct {
	Logger interface{} // *logrus.Logger
}

func (l *LogrusAdapter) Debug(msg string, keyvals ...interface{}) {
	// When using the actual Logrus library:
	// entry := l.Logger.(*logrus.Logger).WithFields(fieldsFromKeyvals(keyvals...))
	// entry.Debug(msg)
	fmt.Printf("[DEBUG] %s %s\n", msg, formatKeyvals(keyvals...))
}

func (l *LogrusAdapter) Info(msg string, keyvals ...interface{}) {
	// When using the actual Logrus library:
	// entry := l.Logger.(*logrus.Logger).WithFields(fieldsFromKeyvals(keyvals...))
	// entry.Info(msg)
	fmt.Printf("[INFO] %s %s\n", msg, formatKeyvals(keyvals...))
}

func (l *LogrusAdapter) Error(msg string, keyvals ...interface{}) {
	// When using the actual Logrus library:
	// entry := l.Logger.(*logrus.Logger).WithFields(fieldsFromKeyvals(keyvals...))
	// entry.Error(msg)
	fmt.Printf("[ERROR] %s %s\n", msg, formatKeyvals(keyvals...))
}

// ------------------------------------------------
// Metrics Adapters
// ------------------------------------------------

// PrometheusAdapter adapts Prometheus metrics to the MetricsRecorder interface.
type PrometheusAdapter struct {
	// Counter metrics
	AuthSuccessCounter interface{} // prometheus.CounterVec
	AuthFailureCounter interface{} // prometheus.CounterVec
	// Histogram metrics
	AuthLatencyHistogram interface{} // prometheus.HistogramVec
}

func (p *PrometheusAdapter) IncAuthSuccess(method string) {
	// When using the actual Prometheus library:
	// p.AuthSuccessCounter.(*prometheus.CounterVec).WithLabelValues(method).Inc()
	fmt.Printf("Incrementing auth success counter for method %s\n", method)
}

func (p *PrometheusAdapter) IncAuthFailure(method string, reason string) {
	// When using the actual Prometheus library:
	// p.AuthFailureCounter.(*prometheus.CounterVec).WithLabelValues(method, reason).Inc()
	fmt.Printf("Incrementing auth failure counter for method %s with reason %s\n", method, reason)
}

func (p *PrometheusAdapter) ObserveAuthLatency(method string, duration time.Duration) {
	// When using the actual Prometheus library:
	// p.AuthLatencyHistogram.(*prometheus.HistogramVec).WithLabelValues(method).Observe(duration.Seconds())
	fmt.Printf("Recording auth latency of %v for method %s\n", duration, method)
}

// ------------------------------------------------
// Tracing Adapters
// ------------------------------------------------

// OpenTelemetryAdapter adapts OpenTelemetry tracing to the Tracer interface.
type OpenTelemetryAdapter struct {
	// This is the actual tracer from OpenTelemetry
	Tracer interface{} // trace.Tracer from "go.opentelemetry.io/otel/trace"
}

func (o *OpenTelemetryAdapter) StartSpan(ctx context.Context, method string) (context.Context, interface{}) {
	// When using the actual OpenTelemetry library:
	// ctx, span := o.Tracer.(trace.Tracer).Start(ctx, "jwt_auth",
	//     trace.WithAttributes(attribute.String("method", method)))
	// return ctx, span
	fmt.Printf("Starting span for method %s\n", method)
	return ctx, "span-placeholder"
}

func (o *OpenTelemetryAdapter) FinishSpan(span interface{}, err error) {
	// When using the actual OpenTelemetry library:
	// if s, ok := span.(trace.Span); ok {
	//     if err != nil {
	//         s.SetStatus(codes.Error, err.Error())
	//     }
	//     s.End()
	// }
	if err != nil {
		fmt.Printf("Finishing span with error: %v\n", err)
	} else {
		fmt.Printf("Finishing span successfully\n")
	}
}

func (o *OpenTelemetryAdapter) AddAttribute(span interface{}, key, value string) {
	// When using the actual OpenTelemetry library:
	// if s, ok := span.(trace.Span); ok {
	//     s.SetAttributes(attribute.String(key, value))
	// }
	fmt.Printf("Adding attribute %s=%s to span\n", key, value)
}

// JaegerAdapter adapts Jaeger tracing to the Tracer interface
type JaegerAdapter struct {
	Tracer interface{} // opentracing.Tracer
}

func (j *JaegerAdapter) StartSpan(ctx context.Context, method string) (context.Context, interface{}) {
	// When using the actual Jaeger/OpenTracing library:
	// var span opentracing.Span
	// if parentSpan := opentracing.SpanFromContext(ctx); parentSpan != nil {
	//     span = j.Tracer.(opentracing.Tracer).StartSpan("jwt_auth",
	//         opentracing.ChildOf(parentSpan.Context()),
	//         opentracing.Tag{Key: "method", Value: method})
	// } else {
	//     span = j.Tracer.(opentracing.Tracer).StartSpan("jwt_auth",
	//         opentracing.Tag{Key: "method", Value: method})
	// }
	// return opentracing.ContextWithSpan(ctx, span), span
	fmt.Printf("Starting Jaeger span for method %s\n", method)
	return ctx, "jaeger-span-placeholder"
}

func (j *JaegerAdapter) FinishSpan(span interface{}, err error) {
	// When using the actual Jaeger/OpenTracing library:
	// if s, ok := span.(opentracing.Span); ok {
	//     if err != nil {
	//         s.SetTag("error", true)
	//         s.SetTag("error.message", err.Error())
	//     }
	//     s.Finish()
	// }
	if err != nil {
		fmt.Printf("Finishing Jaeger span with error: %v\n", err)
	} else {
		fmt.Printf("Finishing Jaeger span successfully\n")
	}
}

func (j *JaegerAdapter) AddAttribute(span interface{}, key, value string) {
	// When using the actual Jaeger/OpenTracing library:
	// if s, ok := span.(opentracing.Span); ok {
	//     s.SetTag(key, value)
	// }
	fmt.Printf("Adding attribute %s=%s to Jaeger span\n", key, value)
}

// ------------------------------------------------
// Helper Functions for Common Libraries
// ------------------------------------------------

// NewStdLogger creates a new StdLogger that wraps the standard logger.
func NewStdLogger(logger *log.Logger) *StdLogger {
	if logger == nil {
		logger = log.Default()
	}
	return &StdLogger{Log: logger}
}

// Integration helpers with full type definitions

// NewOpenTelemetryAdapter creates a properly configured OpenTelemetry adapter
// Example usage:
// import (
//
//	"go.opentelemetry.io/otel"
//	"go.opentelemetry.io/otel/trace"
//
// )
//
// tracer := grpcjwt.NewOpenTelemetryAdapter(otel.GetTracerProvider().Tracer("my-service"))
func NewOpenTelemetryAdapter(tracer interface{}) *OpenTelemetryAdapter {
	return &OpenTelemetryAdapter{
		Tracer: tracer,
	}
}

// NewPrometheusAdapter creates a properly configured Prometheus adapter
// Example usage:
// import (
//
//	"github.com/prometheus/client_golang/prometheus"
//
// )
//
// successCounter := prometheus.NewCounterVec(
//
//	prometheus.CounterOpts{
//	  Name: "jwt_auth_success_total",
//	  Help: "Total successful JWT authentications",
//	},
//	[]string{"method"},
//
// )
//
// failureCounter := prometheus.NewCounterVec(
//
//	prometheus.CounterOpts{
//	  Name: "jwt_auth_failure_total",
//	  Help: "Total failed JWT authentications",
//	},
//	[]string{"method", "reason"},
//
// )
//
// latencyHistogram := prometheus.NewHistogramVec(
//
//	prometheus.HistogramOpts{
//	  Name: "jwt_auth_latency_seconds",
//	  Help: "JWT authentication latency in seconds",
//	  Buckets: prometheus.DefBuckets,
//	},
//	[]string{"method"},
//
// )
//
// metricsRecorder := grpcjwt.NewPrometheusAdapter(successCounter, failureCounter, latencyHistogram)
func NewPrometheusAdapter(successCounter, failureCounter, latencyHistogram interface{}) *PrometheusAdapter {
	return &PrometheusAdapter{
		AuthSuccessCounter:   successCounter,
		AuthFailureCounter:   failureCounter,
		AuthLatencyHistogram: latencyHistogram,
	}
}

// NewZapAdapter creates a properly configured Zap adapter
// Example usage:
// import (
//
//	"go.uber.org/zap"
//
// )
//
// logger, _ := zap.NewProduction()
// sugar := logger.Sugar()
// zapLogger := grpcjwt.NewZapAdapter(sugar)
func NewZapAdapter(logger interface{}) *ZapAdapter {
	return &ZapAdapter{
		Logger: logger,
	}
}
