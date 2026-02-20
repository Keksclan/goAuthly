// Package authlygrpc provides gRPC interceptors for goAuthly.
//
// The interceptors extract credentials from the Authorization metadata header,
// supporting both "Bearer <token>" and "Basic <base64>" schemes, and delegate
// verification to the authly.Engine. On success, the resulting authly.Result
// is injected into the context.
//
// Concurrency: All exported functions are safe for concurrent use.
package authlygrpc

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/keksclan/goAuthly/authly"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey struct{}

// ResultFromContext retrieves the authly.Result stored in the context by the interceptor.
// Returns nil if no result is present.
func ResultFromContext(ctx context.Context) *authly.Result {
	v, _ := ctx.Value(contextKey{}).(*authly.Result)
	return v
}

func contextWithResult(ctx context.Context, r *authly.Result) context.Context {
	return context.WithValue(ctx, contextKey{}, r)
}

// UnaryServerInterceptor returns a gRPC unary server interceptor that authenticates
// requests using the provided authly.Engine.
//
// The interceptor reads the "authorization" metadata key and supports:
//   - "Bearer <token>": verified via engine.Verify
//   - "Basic <base64(user:pass)>": verified via engine.VerifyBasic
//
// On success, the authly.Result is stored in the context and can be retrieved
// with ResultFromContext. On failure, the interceptor returns codes.Unauthenticated.
func UnaryServerInterceptor(engine *authly.Engine) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		newCtx, err := authenticate(ctx, engine)
		if err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor that authenticates
// requests using the provided authly.Engine.
//
// Behavior is identical to UnaryServerInterceptor but for streaming RPCs.
func StreamServerInterceptor(engine *authly.Engine) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		newCtx, err := authenticate(ss.Context(), engine)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: newCtx})
	}
}

// wrappedStream overrides the context of a grpc.ServerStream.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context containing the authly.Result.
func (w *wrappedStream) Context() context.Context { return w.ctx }

func authenticate(ctx context.Context, engine *authly.Engine) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Unauthenticated, "missing metadata")
	}

	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ctx, status.Error(codes.Unauthenticated, "missing authorization header")
	}
	authHeader := vals[0]

	var result *authly.Result
	var err error

	switch {
	case strings.HasPrefix(authHeader, "Basic "):
		result, err = handleBasic(ctx, engine, authHeader[6:])
	case strings.HasPrefix(authHeader, "Bearer "):
		result, err = engine.Verify(ctx, authHeader[7:])
	default:
		return ctx, status.Error(codes.Unauthenticated, "unsupported authorization scheme")
	}

	if err != nil {
		return ctx, status.Error(codes.Unauthenticated, err.Error())
	}

	return contextWithResult(ctx, result), nil
}

func handleBasic(ctx context.Context, engine *authly.Engine, encoded string) (*authly.Result, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid basic auth encoding")
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid basic auth format")
	}
	return engine.VerifyBasic(ctx, username, password)
}
