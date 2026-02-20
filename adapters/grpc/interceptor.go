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

	"github.com/keksclan/goAuthly/adapters/common"
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

// Option configures the gRPC interceptors.
type Option func(*options)

type options struct {
	common.AdapterOptions
}

// WithRequiredMetadata specifies metadata keys that must be present in
// incoming gRPC metadata before authentication proceeds.
func WithRequiredMetadata(keys ...string) Option {
	return func(o *options) {
		o.RequiredMeta.Keys = keys
		o.RequiredMeta.Enabled = true
	}
}

// WithRequiredMetadataEnabled toggles required metadata validation on or off.
func WithRequiredMetadataEnabled(enabled bool) Option {
	return func(o *options) {
		o.RequiredMeta.Enabled = enabled
	}
}

// WithAttachMetadataToResult enables or disables attaching required metadata
// values to the Result.Claims under the "_meta" namespace.
func WithAttachMetadataToResult(attach bool) Option {
	return func(o *options) {
		o.AttachMetaToResult = attach
	}
}

func buildOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
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
func UnaryServerInterceptor(engine *authly.Engine, opts ...Option) grpc.UnaryServerInterceptor {
	o := buildOptions(opts)
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		newCtx, err := authenticate(ctx, engine, &o)
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
func StreamServerInterceptor(engine *authly.Engine, opts ...Option) grpc.StreamServerInterceptor {
	o := buildOptions(opts)
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		newCtx, err := authenticate(ss.Context(), engine, &o)
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

// grpcMetadataExtractor adapts gRPC incoming metadata to the MetadataExtractor interface.
type grpcMetadataExtractor struct {
	md metadata.MD
}

func (e *grpcMetadataExtractor) Get(key string) (string, bool) {
	// gRPC metadata keys are always lower-case.
	vals := e.md.Get(strings.ToLower(key))
	if len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

func (e *grpcMetadataExtractor) All() map[string]string {
	m := make(map[string]string, len(e.md))
	for k, vals := range e.md {
		if len(vals) > 0 {
			m[k] = vals[0]
		}
	}
	return m
}

func authenticate(ctx context.Context, engine *authly.Engine, o *options) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Validate required metadata before auth.
	if o.RequiredMeta.Enabled {
		ex := &grpcMetadataExtractor{md: md}
		if err := o.RequiredMeta.Validate(ex); err != nil {
			return ctx, status.Error(codes.Unauthenticated, err.Error())
		}
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

	// Optionally attach metadata to result.
	if o.AttachMetaToResult && o.RequiredMeta.Enabled {
		ex := &grpcMetadataExtractor{md: md}
		meta := o.RequiredMeta.ExtractMetadataMap(ex)
		common.ApplyMetadataToResult(result, meta, true)
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
