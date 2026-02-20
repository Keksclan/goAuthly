// Package authlyfasthttp provides a fasthttp middleware for goAuthly.
//
// The middleware extracts credentials from the Authorization header,
// supporting both "Bearer <token>" and "Basic <base64>" schemes, and delegates
// verification to the authly.Engine.
//
// On success, the authly.Result is stored in the request context's user value
// under the key "authly". On failure, a 401 response is returned.
//
// Concurrency: All exported functions are safe for concurrent use.
package authlyfasthttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/keksclan/goAuthly/adapters/common"
	"github.com/keksclan/goAuthly/authly"
	"github.com/valyala/fasthttp"
)

// ResultUserValueKey is the key used to store the authly.Result in the
// fasthttp.RequestCtx user values.
const ResultUserValueKey = "authly"

// Option configures the fasthttp middleware.
type Option func(*options)

type options struct {
	common.AdapterOptions
}

// WithRequiredMetadata specifies header keys that must be present in
// incoming HTTP requests before authentication proceeds.
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

// fasthttpMetadataExtractor adapts fasthttp request headers to the MetadataExtractor interface.
type fasthttpMetadataExtractor struct {
	ctx *fasthttp.RequestCtx
}

func (e *fasthttpMetadataExtractor) Get(key string) (string, bool) {
	// fasthttp Peek is case-insensitive for HTTP headers.
	val := string(e.ctx.Request.Header.Peek(key))
	if val == "" {
		return "", false
	}
	return val, true
}

func (e *fasthttpMetadataExtractor) All() map[string]string {
	m := make(map[string]string)
	e.ctx.Request.Header.VisitAll(func(key, value []byte) {
		m[strings.ToLower(string(key))] = string(value)
	})
	return m
}

// Middleware returns a fasthttp request handler that wraps the provided next handler
// with authentication using the given authly.Engine.
//
// The middleware reads the Authorization header and supports:
//   - "Bearer <token>": verified via engine.Verify
//   - "Basic <base64(user:pass)>": verified via engine.VerifyBasic
//
// On success, the authly.Result is stored in ctx.SetUserValue("authly", result)
// and next is called. On failure, a 401 JSON response is written.
func Middleware(engine *authly.Engine, next fasthttp.RequestHandler, opts ...Option) fasthttp.RequestHandler {
	o := buildOptions(opts)
	return func(ctx *fasthttp.RequestCtx) {
		// Validate required metadata before auth.
		if o.RequiredMeta.Enabled {
			ex := &fasthttpMetadataExtractor{ctx: ctx}
			if err := o.RequiredMeta.Validate(ex); err != nil {
				writeUnauthorized(ctx, err.Error())
				return
			}
		}

		authHeader := string(ctx.Request.Header.Peek("Authorization"))
		if authHeader == "" {
			writeUnauthorized(ctx, "missing authorization header")
			return
		}

		bgCtx := context.Background()
		var result *authly.Result
		var err error

		switch {
		case strings.HasPrefix(authHeader, "Basic "):
			result, err = handleBasic(bgCtx, engine, authHeader[6:])
		case strings.HasPrefix(authHeader, "Bearer "):
			result, err = engine.Verify(bgCtx, authHeader[7:])
		default:
			writeUnauthorized(ctx, "unsupported authorization scheme")
			return
		}

		if err != nil {
			writeUnauthorized(ctx, err.Error())
			return
		}

		// Optionally attach metadata to result.
		if o.AttachMetaToResult && o.RequiredMeta.Enabled {
			ex := &fasthttpMetadataExtractor{ctx: ctx}
			meta := o.RequiredMeta.ExtractMetadataMap(ex)
			common.ApplyMetadataToResult(result, meta, true)
		}

		ctx.SetUserValue(ResultUserValueKey, result)
		next(ctx)
	}
}

// ResultFromCtx retrieves the authly.Result stored in the request context by the middleware.
// Returns nil if no result is present or the value is not an *authly.Result.
func ResultFromCtx(ctx *fasthttp.RequestCtx) *authly.Result {
	v, _ := ctx.UserValue(ResultUserValueKey).(*authly.Result)
	return v
}

func writeUnauthorized(ctx *fasthttp.RequestCtx, msg string) {
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.SetContentType("application/json")
	body, _ := json.Marshal(map[string]string{"error": msg})
	ctx.SetBody(body)
}

func handleBasic(ctx context.Context, engine *authly.Engine, encoded string) (*authly.Result, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, &basicAuthError{msg: "invalid basic auth encoding"}
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return nil, &basicAuthError{msg: "invalid basic auth format"}
	}
	return engine.VerifyBasic(ctx, username, password)
}

// basicAuthError is a simple error type for basic auth parsing failures.
type basicAuthError struct {
	msg string
}

func (e *basicAuthError) Error() string { return e.msg }
