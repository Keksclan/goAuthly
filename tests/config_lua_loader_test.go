package tests

import (
	"testing"

	"github.com/keksclan/goAuthly/authly"
	"github.com/keksclan/goAuthly/authlyconfig"
)

func TestLuaLoaderBasicConfig(t *testing.T) {
	script := `
return {
  mode = "oauth2",
  oauth2 = {
    mode = "jwt_and_opaque",
    issuer = "https://issuer.demo",
    audience = "demo-api",
    jwks = {
      url = "http://localhost:8080/.well-known/jwks.json",
      cache_ttl_sec = 900,
      auth = { kind="basic", username="client", password="secret" }
    },
    introspection = {
      endpoint = "http://localhost:8080/introspect",
      timeout_ms = 5000,
      auth = { kind="basic", username="cid", password="csecret" },
      token_transport = { kind="body", field="token" }
    }
  },
  policies = {
    claims = {
      required = {"sub"},
      denylist = {"password", "secret"},
    },
    lua = {
      enabled = true,
      script = [[
        if has("actor") then
          require_claim("sub")
        end
      ]]
    }
  }
}
`
	cfg, err := authlyconfig.LoadLuaString(script)
	if err != nil {
		t.Fatalf("LoadLuaString failed: %v", err)
	}

	if cfg.Mode != authly.AuthModeOAuth2 {
		t.Errorf("mode: want oauth2, got %s", cfg.Mode)
	}
	if cfg.OAuth2.Mode != authly.OAuth2JWTAndOpaque {
		t.Errorf("oauth2.mode: want jwt_and_opaque, got %s", cfg.OAuth2.Mode)
	}
	if cfg.OAuth2.Issuer != "https://issuer.demo" {
		t.Errorf("issuer: want https://issuer.demo, got %s", cfg.OAuth2.Issuer)
	}
	if cfg.OAuth2.Audience != "demo-api" {
		t.Errorf("audience: want demo-api, got %s", cfg.OAuth2.Audience)
	}
	if cfg.OAuth2.JWKSURL != "http://localhost:8080/.well-known/jwks.json" {
		t.Errorf("jwks_url: want http://localhost:8080/.well-known/jwks.json, got %s", cfg.OAuth2.JWKSURL)
	}
	if cfg.OAuth2.JWKSCacheTTL.Seconds() != 900 {
		t.Errorf("jwks_cache_ttl: want 900s, got %v", cfg.OAuth2.JWKSCacheTTL)
	}
	if cfg.OAuth2.JWKS.Auth.Kind != authly.ClientAuthBasic {
		t.Errorf("jwks.auth.kind: want basic, got %s", cfg.OAuth2.JWKS.Auth.Kind)
	}
	if cfg.OAuth2.JWKS.Auth.Username != "client" {
		t.Errorf("jwks.auth.username: want client, got %s", cfg.OAuth2.JWKS.Auth.Username)
	}
	if cfg.OAuth2.Introspection.Endpoint != "http://localhost:8080/introspect" {
		t.Errorf("introspection.endpoint mismatch")
	}
	if cfg.OAuth2.Introspection.Timeout.Milliseconds() != 5000 {
		t.Errorf("introspection.timeout: want 5000ms, got %v", cfg.OAuth2.Introspection.Timeout)
	}
	if cfg.OAuth2.Introspection.Auth.Kind != authly.ClientAuthBasic {
		t.Errorf("introspection.auth.kind: want basic, got %s", cfg.OAuth2.Introspection.Auth.Kind)
	}
	if cfg.OAuth2.Introspection.TokenTransport.Kind != authly.TokenTransportBody {
		t.Errorf("token_transport.kind: want body, got %s", cfg.OAuth2.Introspection.TokenTransport.Kind)
	}
	if cfg.OAuth2.Introspection.TokenTransport.Field != "token" {
		t.Errorf("token_transport.field: want token, got %s", cfg.OAuth2.Introspection.TokenTransport.Field)
	}

	// Policies
	if len(cfg.Policies.TokenClaims.Required) != 1 || cfg.Policies.TokenClaims.Required[0] != "sub" {
		t.Errorf("required claims: want [sub], got %v", cfg.Policies.TokenClaims.Required)
	}
	if len(cfg.Policies.TokenClaims.Denylist) != 2 {
		t.Errorf("denylist: want 2 entries, got %d", len(cfg.Policies.TokenClaims.Denylist))
	}
	if !cfg.Policies.Lua.Enabled {
		t.Errorf("lua.enabled: want true")
	}
	if cfg.Policies.Lua.Script == "" {
		t.Errorf("lua.script: want non-empty")
	}
}

func TestLuaLoaderHeaderTransport(t *testing.T) {
	script := `
return {
  mode = "oauth2",
  oauth2 = {
    mode = "jwt_and_opaque",
    jwks = {
      url = "http://localhost/.well-known/jwks.json"
    },
    introspection = {
      endpoint = "http://localhost/introspect",
      token_transport = { kind="header", header="X-Token", prefix="Bearer " }
    }
  }
}
`
	cfg, err := authlyconfig.LoadLuaString(script)
	if err != nil {
		t.Fatalf("LoadLuaString failed: %v", err)
	}
	if cfg.OAuth2.Introspection.TokenTransport.Kind != authly.TokenTransportHeader {
		t.Errorf("want header transport, got %s", cfg.OAuth2.Introspection.TokenTransport.Kind)
	}
	if cfg.OAuth2.Introspection.TokenTransport.Header != "X-Token" {
		t.Errorf("want X-Token header, got %s", cfg.OAuth2.Introspection.TokenTransport.Header)
	}
	if cfg.OAuth2.Introspection.TokenTransport.Prefix != "Bearer " {
		t.Errorf("want 'Bearer ' prefix, got %q", cfg.OAuth2.Introspection.TokenTransport.Prefix)
	}
}

func TestLuaLoaderInvalidScript(t *testing.T) {
	script := `this is not valid lua`
	_, err := authlyconfig.LoadLuaString(script)
	if err == nil {
		t.Fatal("expected error for invalid lua")
	}
}

func TestLuaLoaderMissingReturn(t *testing.T) {
	script := `local x = 1`
	_, err := authlyconfig.LoadLuaString(script)
	if err == nil {
		t.Fatal("expected error when lua does not return a table")
	}
}

func TestLuaLoaderValidationFails(t *testing.T) {
	// Missing required fields
	script := `
return {
  mode = "oauth2",
  oauth2 = {
    mode = "jwt_only"
    -- missing jwks url
  }
}
`
	_, err := authlyconfig.LoadLuaString(script)
	if err == nil {
		t.Fatal("expected validation error for missing jwks_url")
	}
}
