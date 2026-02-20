// Package authlyfiber provides a Fiber middleware for goAuthly.
//
// The middleware extracts credentials from the Authorization header,
// supporting both "Bearer <token>" and "Basic <base64>" schemes, and delegates
// verification to the authly.Engine.
//
// On success, the authly.Result is stored in c.Locals("authly").
// On failure, a 401 JSON response is returned.
//
// Concurrency: All exported functions are safe for concurrent use.
package authlyfiber

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/keksclan/goAuthly/adapters/common"
	"github.com/keksclan/goAuthly/authly"
)

// Option configures the Fiber middleware.
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

// fiberMetadataExtractor adapts Fiber request headers to the MetadataExtractor interface.
type fiberMetadataExtractor struct {
	c *fiber.Ctx
}

func (e *fiberMetadataExtractor) Get(key string) (string, bool) {
	// Fiber's c.Get is case-insensitive for HTTP headers.
	val := e.c.Get(key)
	if val == "" {
		return "", false
	}
	return val, true
}

func (e *fiberMetadataExtractor) All() map[string]string {
	m := make(map[string]string)
	e.c.Request().Header.VisitAll(func(key, value []byte) {
		m[strings.ToLower(string(key))] = string(value)
	})
	return m
}

// Middleware returns a Fiber middleware that authenticates requests using
// the provided authly.Engine.
//
// The middleware reads the Authorization header and supports:
//   - "Bearer <token>": verified via engine.Verify
//   - "Basic <base64(user:pass)>": verified via engine.VerifyBasic
//
// On success, the authly.Result is stored in c.Locals("authly") and the
// request proceeds to the next handler. On failure, a 401 JSON response
// is returned with an "error" field describing the issue.
func Middleware(engine *authly.Engine, opts ...Option) fiber.Handler {
	o := buildOptions(opts)
	return func(c *fiber.Ctx) error {
		// Validate required metadata before auth.
		if o.RequiredMeta.Enabled {
			ex := &fiberMetadataExtractor{c: c}
			if err := o.RequiredMeta.Validate(ex); err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
		}

		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing authorization header",
			})
		}

		ctx := context.Background()
		var result *authly.Result
		var err error

		switch {
		case strings.HasPrefix(authHeader, "Basic "):
			result, err = handleBasic(ctx, engine, authHeader[6:])
		case strings.HasPrefix(authHeader, "Bearer "):
			result, err = engine.Verify(ctx, authHeader[7:])
		default:
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "unsupported authorization scheme",
			})
		}

		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Optionally attach metadata to result.
		if o.AttachMetaToResult && o.RequiredMeta.Enabled {
			ex := &fiberMetadataExtractor{c: c}
			meta := o.RequiredMeta.ExtractMetadataMap(ex)
			common.ApplyMetadataToResult(result, meta, true)
		}

		c.Locals("authly", result)
		return c.Next()
	}
}

// ResultFromLocals retrieves the authly.Result stored by the middleware.
// Returns nil if no result is present or the value is not an *authly.Result.
func ResultFromLocals(c *fiber.Ctx) *authly.Result {
	v, _ := c.Locals("authly").(*authly.Result)
	return v
}

func handleBasic(ctx context.Context, engine *authly.Engine, encoded string) (*authly.Result, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "invalid basic auth encoding")
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "invalid basic auth format")
	}
	return engine.VerifyBasic(ctx, username, password)
}
