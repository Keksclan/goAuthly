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

type Client struct {
	endpoint     string
	httpc        *http.Client
	clientID     string
	clientSecret string
}

type Config struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	Timeout      time.Duration
}

func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	return &Client{
		endpoint:     cfg.Endpoint,
		httpc:        &http.Client{Timeout: cfg.Timeout},
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
	}, nil
}

func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.clientID != "" {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
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
