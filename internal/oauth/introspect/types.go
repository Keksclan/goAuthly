package introspect

type IntrospectionResponse struct {
	Active    bool           `json:"active"`
	Scope     string         `json:"scope,omitempty"`
	ClientID  string         `json:"client_id,omitempty"`
	Username  string         `json:"username,omitempty"`
	TokenType string         `json:"token_type,omitempty"`
	Exp       int64          `json:"exp,omitempty"`
	Iat       int64          `json:"iat,omitempty"`
	Nbf       int64          `json:"nbf,omitempty"`
	Sub       string         `json:"sub,omitempty"`
	Aud       any            `json:"aud,omitempty"`
	Iss       string         `json:"iss,omitempty"`
	Jti       string         `json:"jti,omitempty"`
	Extras    map[string]any `json:"-"`
}
