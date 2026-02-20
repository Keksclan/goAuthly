package authlyconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/keksclan/goAuthly/authly"
	lua "github.com/yuin/gopher-lua"
)

// Loader loads an authly.Config from a source.
type Loader interface {
	Load(ctx context.Context) (*authly.Config, error)
}

// goLoader returns a static config.
type goLoader struct {
	cfg authly.Config
}

// FromGo creates a Loader that returns the provided config directly.
func FromGo(cfg authly.Config) Loader {
	return &goLoader{cfg: cfg}
}

func (l *goLoader) Load(_ context.Context) (*authly.Config, error) {
	cfg := l.cfg
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}
	return &cfg, nil
}

// jsonLoader loads config from a JSON file.
type jsonLoader struct {
	path string
}

// FromJSONFile creates a Loader that reads config from a JSON file.
func FromJSONFile(path string) Loader {
	return &jsonLoader{path: path}
}

// jsonConfig mirrors authly.Config for JSON deserialization.
type jsonConfig struct {
	Mode     string       `json:"mode"`
	OAuth2   jsonOAuth2   `json:"oauth2"`
	Policies jsonPolicies `json:"policies"`
}

type jsonOAuth2 struct {
	Mode                  string            `json:"mode"`
	Issuer                string            `json:"issuer"`
	Audience              string            `json:"audience"`
	AllowedAlgs           []string          `json:"allowed_algs"`
	JWKSURL               string            `json:"jwks_url"`
	JWKSCacheTTL          int               `json:"jwks_cache_ttl_sec"`
	AllowStaleJWKS        bool              `json:"allow_stale_jwks"`
	JWKS                  jsonJWKS          `json:"jwks"`
	Introspection         jsonIntrospection `json:"introspection"`
	IntrospectionCacheTTL int               `json:"introspection_cache_ttl_sec"`
	Opaque                jsonOpaque        `json:"opaque"`
}

type jsonJWKS struct {
	URL          string            `json:"url"`
	CacheTTLSec  int               `json:"cache_ttl_sec"`
	Auth         jsonJWKSAuth      `json:"auth"`
	ExtraHeaders map[string]string `json:"extra_headers"`
}

type jsonJWKSAuth struct {
	Kind        string `json:"kind"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	HeaderName  string `json:"header_name"`
	HeaderValue string `json:"header_value"`
	BearerToken string `json:"bearer_token"`
}

type jsonIntrospection struct {
	Endpoint       string             `json:"endpoint"`
	TimeoutMs      int                `json:"timeout_ms"`
	Auth           jsonClientAuth     `json:"auth"`
	TokenTransport jsonTokenTransport `json:"token_transport"`
	ExtraBody      map[string]string  `json:"extra_body"`
	ExtraHeaders   map[string]string  `json:"extra_headers"`
}

type jsonClientAuth struct {
	Kind         string `json:"kind"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	HeaderName   string `json:"header_name"`
	HeaderValue  string `json:"header_value"`
}

type jsonTokenTransport struct {
	Kind   string `json:"kind"`
	Field  string `json:"field"`
	Header string `json:"header"`
	Prefix string `json:"prefix"`
}

type jsonOpaque struct {
	RequireActive     bool `json:"require_active"`
	ExposeActiveClaim bool `json:"expose_active_claim"`
}

type jsonPolicies struct {
	Claims jsonClaimsPolicies `json:"claims"`
	Lua    jsonLuaPolicy      `json:"lua"`
}

type jsonClaimsPolicies struct {
	Required []string `json:"required"`
	Denylist []string `json:"denylist"`
}

type jsonLuaPolicy struct {
	Enabled bool   `json:"enabled"`
	Script  string `json:"script"`
}

func (l *jsonLoader) Load(_ context.Context) (*authly.Config, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("read json config: %w", err)
	}
	var jc jsonConfig
	if err := json.Unmarshal(data, &jc); err != nil {
		return nil, fmt.Errorf("parse json config: %w", err)
	}
	cfg := jsonToConfig(jc)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}
	return &cfg, nil
}

func jsonToConfig(jc jsonConfig) authly.Config {
	cfg := authly.Config{
		Mode: authly.AuthMode(jc.Mode),
		OAuth2: authly.OAuth2Config{
			Mode:           authly.OAuth2Mode(jc.OAuth2.Mode),
			Issuer:         jc.OAuth2.Issuer,
			Audience:       jc.OAuth2.Audience,
			AllowedAlgs:    jc.OAuth2.AllowedAlgs,
			JWKSURL:        jc.OAuth2.JWKSURL,
			JWKSCacheTTL:   time.Duration(jc.OAuth2.JWKSCacheTTL) * time.Second,
			AllowStaleJWKS: jc.OAuth2.AllowStaleJWKS,
			JWKS: authly.JWKSConfig{
				URL:      jc.OAuth2.JWKS.URL,
				CacheTTL: time.Duration(jc.OAuth2.JWKS.CacheTTLSec) * time.Second,
				Auth: authly.JWKSAuth{
					Kind:        authly.ClientAuthKind(jc.OAuth2.JWKS.Auth.Kind),
					Username:    jc.OAuth2.JWKS.Auth.Username,
					Password:    jc.OAuth2.JWKS.Auth.Password,
					HeaderName:  jc.OAuth2.JWKS.Auth.HeaderName,
					HeaderValue: jc.OAuth2.JWKS.Auth.HeaderValue,
					BearerToken: jc.OAuth2.JWKS.Auth.BearerToken,
				},
				ExtraHeaders: jc.OAuth2.JWKS.ExtraHeaders,
			},
			Introspection: authly.IntrospectionConfig{
				Endpoint: jc.OAuth2.Introspection.Endpoint,
				Timeout:  time.Duration(jc.OAuth2.Introspection.TimeoutMs) * time.Millisecond,
				Auth: authly.ClientAuth{
					Kind:         authly.ClientAuthKind(jc.OAuth2.Introspection.Auth.Kind),
					ClientID:     jc.OAuth2.Introspection.Auth.ClientID,
					ClientSecret: jc.OAuth2.Introspection.Auth.ClientSecret,
					HeaderName:   jc.OAuth2.Introspection.Auth.HeaderName,
					HeaderValue:  jc.OAuth2.Introspection.Auth.HeaderValue,
				},
				TokenTransport: authly.TokenTransport{
					Kind:   authly.TokenTransportKind(jc.OAuth2.Introspection.TokenTransport.Kind),
					Field:  jc.OAuth2.Introspection.TokenTransport.Field,
					Header: jc.OAuth2.Introspection.TokenTransport.Header,
					Prefix: jc.OAuth2.Introspection.TokenTransport.Prefix,
				},
				ExtraBody:    jc.OAuth2.Introspection.ExtraBody,
				ExtraHeaders: jc.OAuth2.Introspection.ExtraHeaders,
			},
			IntrospectionCacheTTL: time.Duration(jc.OAuth2.IntrospectionCacheTTL) * time.Second,
			Opaque: authly.OpaquePolicy{
				RequireActive:     jc.OAuth2.Opaque.RequireActive,
				ExposeActiveClaim: jc.OAuth2.Opaque.ExposeActiveClaim,
			},
		},
		Policies: authly.Policies{
			TokenClaims: authly.ClaimPolicy{
				Required: jc.Policies.Claims.Required,
				Denylist: jc.Policies.Claims.Denylist,
			},
			Lua: authly.LuaClaimsPolicy{
				Enabled: jc.Policies.Lua.Enabled,
				Script:  jc.Policies.Lua.Script,
			},
		},
	}
	// If JWKS URL is set via nested config, use it as fallback for top-level JWKSURL
	if cfg.OAuth2.JWKSURL == "" && cfg.OAuth2.JWKS.URL != "" {
		cfg.OAuth2.JWKSURL = cfg.OAuth2.JWKS.URL
	}
	return cfg
}

// luaLoader loads config from a Lua file.
type luaLoader struct {
	path string
}

// FromLuaFile creates a Loader that reads config from a Lua file.
func FromLuaFile(path string) Loader {
	return &luaLoader{path: path}
}

func (l *luaLoader) Load(_ context.Context) (*authly.Config, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("read lua config file: %w", err)
	}
	return LoadLuaString(string(data))
}

// LoadLuaString parses a Lua config string and returns an authly.Config.
// Exported for testing convenience.
func LoadLuaString(script string) (*authly.Config, error) {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()

	// Only open safe libs for config parsing
	for _, pair := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.LoadLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		L.Push(L.NewFunction(pair.fn))
		L.Push(lua.LString(pair.name))
		L.Call(1, 0)
	}
	// Remove dangerous functions
	L.SetGlobal("dofile", lua.LNil)
	L.SetGlobal("loadfile", lua.LNil)
	L.SetGlobal("load", lua.LNil)
	L.SetGlobal("loadstring", lua.LNil)

	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("lua config execution: %w", err)
	}

	ret := L.Get(-1)
	tbl, ok := ret.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("lua config must return a table, got %s", ret.Type().String())
	}

	cfg, err := luaTableToConfig(tbl)
	if err != nil {
		return nil, fmt.Errorf("lua config mapping: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

func luaTableToConfig(tbl *lua.LTable) (*authly.Config, error) {
	cfg := &authly.Config{}

	cfg.Mode = authly.AuthMode(getStringField(tbl, "mode"))

	oauth2Tbl := getTableField(tbl, "oauth2")
	if oauth2Tbl != nil {
		cfg.OAuth2.Mode = authly.OAuth2Mode(getStringField(oauth2Tbl, "mode"))
		cfg.OAuth2.Issuer = getStringField(oauth2Tbl, "issuer")
		cfg.OAuth2.Audience = getStringField(oauth2Tbl, "audience")
		cfg.OAuth2.AllowedAlgs = getStringSliceField(oauth2Tbl, "allowed_algs")

		// JWKS config
		jwksTbl := getTableField(oauth2Tbl, "jwks")
		if jwksTbl != nil {
			cfg.OAuth2.JWKSURL = getStringField(jwksTbl, "url")
			cfg.OAuth2.JWKS.URL = cfg.OAuth2.JWKSURL
			cacheTTL := getNumberField(jwksTbl, "cache_ttl_sec")
			if cacheTTL > 0 {
				cfg.OAuth2.JWKSCacheTTL = time.Duration(cacheTTL) * time.Second
				cfg.OAuth2.JWKS.CacheTTL = cfg.OAuth2.JWKSCacheTTL
			}

			authTbl := getTableField(jwksTbl, "auth")
			if authTbl != nil {
				cfg.OAuth2.JWKS.Auth.Kind = authly.ClientAuthKind(getStringField(authTbl, "kind"))
				cfg.OAuth2.JWKS.Auth.Username = getStringField(authTbl, "username")
				cfg.OAuth2.JWKS.Auth.Password = getStringField(authTbl, "password")
				cfg.OAuth2.JWKS.Auth.HeaderName = getStringField(authTbl, "header_name")
				cfg.OAuth2.JWKS.Auth.HeaderValue = getStringField(authTbl, "header_value")
				cfg.OAuth2.JWKS.Auth.BearerToken = getStringField(authTbl, "bearer_token")
			}
			cfg.OAuth2.JWKS.ExtraHeaders = getStringMapField(jwksTbl, "extra_headers")
		}

		// Introspection config
		introTbl := getTableField(oauth2Tbl, "introspection")
		if introTbl != nil {
			cfg.OAuth2.Introspection.Endpoint = getStringField(introTbl, "endpoint")
			timeoutMs := getNumberField(introTbl, "timeout_ms")
			if timeoutMs > 0 {
				cfg.OAuth2.Introspection.Timeout = time.Duration(timeoutMs) * time.Millisecond
			}

			authTbl := getTableField(introTbl, "auth")
			if authTbl != nil {
				cfg.OAuth2.Introspection.Auth.Kind = authly.ClientAuthKind(getStringField(authTbl, "kind"))
				cfg.OAuth2.Introspection.Auth.ClientID = getStringField(authTbl, "username")
				cfg.OAuth2.Introspection.Auth.ClientSecret = getStringField(authTbl, "password")
				// Also support client_id/client_secret keys
				if cid := getStringField(authTbl, "client_id"); cid != "" {
					cfg.OAuth2.Introspection.Auth.ClientID = cid
				}
				if cs := getStringField(authTbl, "client_secret"); cs != "" {
					cfg.OAuth2.Introspection.Auth.ClientSecret = cs
				}
				cfg.OAuth2.Introspection.Auth.HeaderName = getStringField(authTbl, "header_name")
				cfg.OAuth2.Introspection.Auth.HeaderValue = getStringField(authTbl, "header_value")
			}

			ttTbl := getTableField(introTbl, "token_transport")
			if ttTbl != nil {
				cfg.OAuth2.Introspection.TokenTransport.Kind = authly.TokenTransportKind(getStringField(ttTbl, "kind"))
				cfg.OAuth2.Introspection.TokenTransport.Field = getStringField(ttTbl, "field")
				cfg.OAuth2.Introspection.TokenTransport.Header = getStringField(ttTbl, "header")
				cfg.OAuth2.Introspection.TokenTransport.Prefix = getStringField(ttTbl, "prefix")
			}

			cfg.OAuth2.Introspection.ExtraBody = getStringMapField(introTbl, "extra_body")
			cfg.OAuth2.Introspection.ExtraHeaders = getStringMapField(introTbl, "extra_headers")
		}
	}

	// Policies
	policiesTbl := getTableField(tbl, "policies")
	if policiesTbl != nil {
		claimsTbl := getTableField(policiesTbl, "claims")
		if claimsTbl != nil {
			cfg.Policies.TokenClaims.Required = getStringSliceField(claimsTbl, "required")
			cfg.Policies.TokenClaims.Denylist = getStringSliceField(claimsTbl, "denylist")
		}

		luaTbl := getTableField(policiesTbl, "lua")
		if luaTbl != nil {
			cfg.Policies.Lua.Enabled = getBoolField(luaTbl, "enabled")
			cfg.Policies.Lua.Script = getStringField(luaTbl, "script")
		}
	}

	return cfg, nil
}

// Lua table helper functions

func getStringField(tbl *lua.LTable, key string) string {
	v := tbl.RawGetString(key)
	if s, ok := v.(lua.LString); ok {
		return string(s)
	}
	return ""
}

func getNumberField(tbl *lua.LTable, key string) float64 {
	v := tbl.RawGetString(key)
	if n, ok := v.(lua.LNumber); ok {
		return float64(n)
	}
	return 0
}

func getBoolField(tbl *lua.LTable, key string) bool {
	v := tbl.RawGetString(key)
	if b, ok := v.(lua.LBool); ok {
		return bool(b)
	}
	return false
}

func getTableField(tbl *lua.LTable, key string) *lua.LTable {
	v := tbl.RawGetString(key)
	if t, ok := v.(*lua.LTable); ok {
		return t
	}
	return nil
}

func getStringSliceField(tbl *lua.LTable, key string) []string {
	v := tbl.RawGetString(key)
	t, ok := v.(*lua.LTable)
	if !ok {
		return nil
	}
	var result []string
	t.ForEach(func(_ lua.LValue, val lua.LValue) {
		if s, ok := val.(lua.LString); ok {
			result = append(result, string(s))
		}
	})
	return result
}

func getStringMapField(tbl *lua.LTable, key string) map[string]string {
	v := tbl.RawGetString(key)
	t, ok := v.(*lua.LTable)
	if !ok {
		return nil
	}
	result := make(map[string]string)
	t.ForEach(func(k lua.LValue, val lua.LValue) {
		if ks, ok := k.(lua.LString); ok {
			if vs, ok := val.(lua.LString); ok {
				result[string(ks)] = string(vs)
			}
		}
	})
	if len(result) == 0 {
		return nil
	}
	return result
}
