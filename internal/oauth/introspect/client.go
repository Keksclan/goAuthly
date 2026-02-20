package introspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrTokenInactive = errors.New("token is inactive")

// maxResponseSize limits the size of introspection HTTP responses to prevent memory bombs.
const maxResponseSize = 1 << 20 // 1 MB

// defaultTimeout is the fallback HTTP client timeout when none, zero, or negative is configured.
const defaultTimeout = 5 * time.Second

// TokenTransportKind selects how the token is delivered.
type TokenTransportKind string

const (
	TokenTransportBody   TokenTransportKind = "body"
	TokenTransportHeader TokenTransportKind = "header"
)

// TokenTransport controls how the token is delivered to the introspection endpoint.
type TokenTransport struct {
	Kind   TokenTransportKind
	Field  string // body field name, default "token"
	Header string // header name when Kind == header
	Prefix string // header value prefix when Kind == header
}

// ClientAuthKind selects how client credentials are sent.
type ClientAuthKind string

const (
	ClientAuthNone   ClientAuthKind = "none"
	ClientAuthBasic  ClientAuthKind = "basic"
	ClientAuthBody   ClientAuthKind = "body"
	ClientAuthHeader ClientAuthKind = "header"
	ClientAuthBearer ClientAuthKind = "bearer"
)

// ClientAuth configures client authentication.
type ClientAuth struct {
	Kind         ClientAuthKind
	ClientID     string
	ClientSecret string
	HeaderName   string
	HeaderValue  string
}

type Client struct {
	endpoint       string
	httpc          *http.Client
	clientID       string
	clientSecret   string
	auth           ClientAuth
	tokenTransport TokenTransport
	extraBody      map[string]string
	extraHeaders   map[string]string
}

type Config struct {
	Endpoint       string
	ClientID       string
	ClientSecret   string
	Timeout        time.Duration
	Auth           ClientAuth
	TokenTransport TokenTransport
	ExtraBody      map[string]string
	ExtraHeaders   map[string]string
}

func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	tt := cfg.TokenTransport
	if tt.Kind == "" {
		tt.Kind = TokenTransportBody
	}
	if tt.Kind == TokenTransportBody && tt.Field == "" {
		tt.Field = "token"
	}
	if tt.Kind == TokenTransportHeader && tt.Header == "" {
		tt.Header = "Authorization"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		endpoint:       cfg.Endpoint,
		httpc:          &http.Client{Timeout: timeout},
		clientID:       cfg.ClientID,
		clientSecret:   cfg.ClientSecret,
		auth:           cfg.Auth,
		tokenTransport: tt,
		extraBody:      cfg.ExtraBody,
		extraHeaders:   cfg.ExtraHeaders,
	}, nil
}

func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	data := url.Values{}

	// Token transport: body or header
	if c.tokenTransport.Kind == TokenTransportBody || c.tokenTransport.Kind == "" {
		data.Set(c.tokenTransport.Field, token)
	}

	// Extra body params
	for k, v := range c.extraBody {
		data.Set(k, v)
	}

	// Legacy body auth: add client_id/client_secret to form
	if c.auth.Kind == ClientAuthBody {
		if c.auth.ClientID != "" {
			data.Set("client_id", c.auth.ClientID)
		}
		if c.auth.ClientSecret != "" {
			data.Set("client_secret", c.auth.ClientSecret)
		}
	}

	var bodyReader *strings.Reader
	if len(data) > 0 {
		bodyReader = strings.NewReader(data.Encode())
	} else {
		bodyReader = strings.NewReader("")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Token transport: header
	if c.tokenTransport.Kind == TokenTransportHeader {
		req.Header.Set(c.tokenTransport.Header, c.tokenTransport.Prefix+token)
	}

	// Apply client auth
	c.applyAuth(req)

	// Extra headers
	for k, v := range c.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var fullResponse map[string]any
	if err := json.Unmarshal(body, &fullResponse); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	var introResp IntrospectionResponse
	if err := json.Unmarshal(body, &introResp); err != nil {
		return nil, fmt.Errorf("failed to map introspection response: %w", err)
	}

	// Capture extras
	knownFields := map[string]bool{
		"active": true, "scope": true, "client_id": true, "username": true,
		"token_type": true, "exp": true, "iat": true, "nbf": true,
		"sub": true, "aud": true, "iss": true, "jti": true,
	}

	introResp.Extras = make(map[string]any)
	for k, v := range fullResponse {
		if !knownFields[k] {
			introResp.Extras[k] = v
		}
	}

	if !introResp.Active {
		return &introResp, ErrTokenInactive
	}

	return &introResp, nil
}

func (c *Client) applyAuth(req *http.Request) {
	switch c.auth.Kind {
	case ClientAuthBasic:
		req.SetBasicAuth(c.auth.ClientID, c.auth.ClientSecret)
	case ClientAuthBearer:
		req.Header.Set("Authorization", "Bearer "+c.auth.ClientSecret)
	case ClientAuthHeader:
		if c.auth.HeaderName != "" {
			req.Header.Set(c.auth.HeaderName, c.auth.HeaderValue)
		}
	case ClientAuthBody:
		// already handled in body construction
	case ClientAuthNone, "":
		// Backward compatibility: use legacy clientID/clientSecret for basic auth
		if c.clientID != "" {
			req.SetBasicAuth(c.clientID, c.clientSecret)
		}
	}
}
