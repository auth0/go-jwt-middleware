package jwtmiddleware

import (
	"context"
	"errors"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
)

var (
	// ErrJWTMissing is returned when the JWT is missing.
	ErrJWTMissing = errors.New("jwt missing")

	// ErrJWTInvalid is returned when the JWT is invalid.
	ErrJWTInvalid = errors.New("jwt invalid")
)

// ErrorHandler is a handler which is called when an error occurs in the
// JWTMiddleware. Among some general errors, this handler also determines the
// response of the JWTMiddleware when a token is not found or is invalid. The
// err can be checked to be ErrJWTMissing or ErrJWTInvalid for specific cases.
// The default handler will return a status code of 400 for ErrJWTMissing,
// 401 for ErrJWTInvalid, and 500 for all other errors. If you implement your
// own ErrorHandler you MUST take into consideration the error types as not
// properly responding to them or having a poorly implemented handler could
// result in the JWTMiddleware not functioning as intended.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// DefaultErrorHandler is the default error handler implementation for the
// JWTMiddleware. If an error handler is not provided via the WithErrorHandler
// option this will be used.
func DefaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	switch {
	case errors.Is(err, ErrJWTMissing):
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"JWT is missing."}`))
	case errors.Is(err, ErrJWTInvalid):
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"JWT is invalid."}`))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"Something went wrong while checking the JWT."}`))
	}
}

// invalidError handles wrapping a JWT validation error with
// the concrete error ErrJWTInvalid. We do not expose this
// publicly because the interface methods of Is and Unwrap
// should give the user all they need.
type invalidError struct {
	details error
}

// Is allows the error to support equality to ErrJWTInvalid.
func (e invalidError) Is(target error) bool {
	return target == ErrJWTInvalid
}

// Error returns a string representation of the error.
func (e invalidError) Error() string {
	return fmt.Sprintf("%s: %s", ErrJWTInvalid, e.details)
}

// Unwrap allows the error to support equality to the
// underlying error and not just ErrJWTInvalid.
func (e invalidError) Unwrap() error {
	return e.details
}

type GrpcErrorHandler struct {
	GrpcUnaryErrorHandler
	GrpcStreamErrorHandler
}

type GrpcUnaryErrorHandler func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler, err error) (any, error)
type GrpcStreamErrorHandler func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler, err error) error

func DefaultGrpcErrorHandler() GrpcErrorHandler {
	return GrpcErrorHandler{
		GrpcUnaryErrorHandler:  DefaultGrpcUnaryErrorHandler,
		GrpcStreamErrorHandler: DefaultGrpcStreamErrorHandler,
	}
}

func DefaultGrpcUnaryErrorHandler(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler, err error) (any, error) {
	if err != nil {
		switch {
		case errors.Is(err, ErrJWTMissing):
			return nil, status.Errorf(codes.InvalidArgument, "%s", ErrJWTMissing.Error())
		case errors.Is(err, ErrJWTInvalid):
			return nil, status.Errorf(codes.Unauthenticated, "%s", ErrJWTInvalid.Error())
		default:
			return nil, status.Errorf(codes.Internal, "%s", err.Error())
		}
	}

	return handler(ctx, req)
}

func DefaultGrpcStreamErrorHandler(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler, err error) error {
	if err != nil {
		switch {
		case errors.Is(err, ErrJWTMissing):
			return status.Errorf(codes.InvalidArgument, "%s", ErrJWTMissing.Error())
		case errors.Is(err, ErrJWTInvalid):
			return status.Errorf(codes.Unauthenticated, "%s", ErrJWTInvalid.Error())
		default:
			return status.Errorf(codes.Internal, "%s", err.Error())
		}
	}

	return handler(srv, newWrappedStream(ss))
}
