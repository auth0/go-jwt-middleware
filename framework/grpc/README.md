# gRPC JWT Middleware

This package provides JWT authentication middleware for gRPC services. It integrates with the core `go-jwt-middleware` package to provide a consistent authentication experience across HTTP and gRPC services.

## Features

- JWT authentication for gRPC Unary and Stream RPCs
- Token extraction from gRPC metadata
- Configurable using functional options
- Exclusion of specific methods from authentication
- Support for optional credentials
- Easy access to validated claims from context
- Comprehensive logging support
- Metrics tracking for authentication operations
- Distributed tracing integration
- Adapters for popular logging, metrics, and tracing libraries

## Installation

```go
go get github.com/kunal-dawar/go-jwt-middleware/grpc
```

## Basic Usage

```go
import (
    "github.com/auth0/go-jwt-middleware/v2/validator"
    grpcjwt "github.com/kunal-dawar/go-jwt-middleware/grpc"
    "google.golang.org/grpc"
)

func main() {
    // Create a validator
    // In a real app, use proper key management
    keyFunc := func(ctx context.Context) (interface{}, error) {
        return []byte("your-secret"), nil
    }

    jwtValidator, _ := validator.New(
        validator.WithKeyFunc(keyFunc),
        validator.WithSignatureAlgorithm(validator.HS256),
        validator.WithIssuer("issuer"),
        validator.WithAudience("audience"),
    )

    validateFunc := func(ctx context.Context, token string) (interface{}, error) {
        return jwtValidator.ValidateToken(ctx, token)
    }

    // Create the interceptor
    interceptor := grpcjwt.New(
        validateFunc,
        grpcjwt.WithCredentialsOptional(false),
        grpcjwt.WithExclusionMethods([]string{"/health.service/Check"}),
    )

    // Create gRPC server with the JWT interceptor
    server := grpc.NewServer(
        grpc.UnaryInterceptor(interceptor.UnaryServerInterceptor()),
        grpc.StreamInterceptor(interceptor.StreamServerInterceptor()),
    )

    // Register your services and start the server
    // ...
}
```

## Logging Integration

```go
import (
    "log"
    "os"
    grpcjwt "github.com/kunal-dawar/go-jwt-middleware/grpc"
)

// Using the standard logger
stdLogger := log.New(os.Stdout, "[JWT] ", log.LstdFlags)
loggerAdapter := grpcjwt.NewStdLogger(stdLogger)

interceptor := grpcjwt.New(
    validateFunc,
    grpcjwt.WithLogger(loggerAdapter),
)

// Custom logger implementation
type MyLogger struct {
    // Your logger fields
}

func (l *MyLogger) Debug(msg string, keyvals ...interface{}) {
    // Your implementation
}

func (l *MyLogger) Info(msg string, keyvals ...interface{}) {
    // Your implementation
}

func (l *MyLogger) Error(msg string, keyvals ...interface{}) {
    // Your implementation
}

interceptor := grpcjwt.New(
    validateFunc,
    grpcjwt.WithLogger(&MyLogger{}),
)
```

## Metrics Integration

```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    grpcjwt "github.com/kunal-dawar/go-jwt-middleware/grpc"
)

// Create Prometheus metrics
authSuccess := promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "grpc_jwt_auth_success_total",
        Help: "Total number of successful JWT authentications",
    },
    []string{"method"},
)

authFailure := promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "grpc_jwt_auth_failure_total",
        Help: "Total number of failed JWT authentications",
    },
    []string{"method", "reason"},
)

authLatency := promauto.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "grpc_jwt_auth_latency_seconds",
        Help:    "JWT authentication latency in seconds",
        Buckets: prometheus.DefBuckets,
    },
    []string{"method"},
)

// Create a metrics adapter
type PrometheusMetrics struct {
    successCounter *prometheus.CounterVec
    failureCounter *prometheus.CounterVec
    latencyHistogram *prometheus.HistogramVec
}

func (p *PrometheusMetrics) IncAuthSuccess(method string) {
    p.successCounter.WithLabelValues(method).Inc()
}

func (p *PrometheusMetrics) Inc
```
