package tests

import (
	"errors"
	"strings"
	"testing"

	"github.com/keksclan/goAuthly/adapters/common"
	"github.com/keksclan/goAuthly/authly"
)

// mapExtractor is a simple MetadataExtractor backed by a map.
// It supports case-insensitive lookups to simulate HTTP header behavior.
type mapExtractor struct {
	data          map[string]string
	caseSensitive bool
}

func (e *mapExtractor) Get(key string) (string, bool) {
	if e.caseSensitive {
		v, ok := e.data[key]
		return v, ok
	}
	// Case-insensitive lookup (HTTP-style).
	for k, v := range e.data {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func (e *mapExtractor) All() map[string]string {
	m := make(map[string]string, len(e.data))
	for k, v := range e.data {
		m[strings.ToLower(k)] = v
	}
	return m
}

func TestRequiredMetadataValidate(t *testing.T) {
	tests := []struct {
		name    string
		meta    common.RequiredMetadata
		data    map[string]string
		wantErr bool
	}{
		{
			name: "disabled skips validation",
			meta: common.RequiredMetadata{Keys: []string{"X-User-Sub"}, Enabled: false},
			data: map[string]string{},
		},
		{
			name: "no keys skips validation",
			meta: common.RequiredMetadata{Keys: nil, Enabled: true},
			data: map[string]string{},
		},
		{
			name: "required key present",
			meta: common.RequiredMetadata{Keys: []string{"X-User-Sub"}, Enabled: true},
			data: map[string]string{"X-User-Sub": "user-123"},
		},
		{
			name:    "required key missing",
			meta:    common.RequiredMetadata{Keys: []string{"X-User-Sub"}, Enabled: true},
			data:    map[string]string{},
			wantErr: true,
		},
		{
			name:    "required key empty",
			meta:    common.RequiredMetadata{Keys: []string{"X-User-Sub"}, Enabled: true},
			data:    map[string]string{"X-User-Sub": ""},
			wantErr: true,
		},
		{
			name:    "required key whitespace only",
			meta:    common.RequiredMetadata{Keys: []string{"X-User-Sub"}, Enabled: true},
			data:    map[string]string{"X-User-Sub": "   "},
			wantErr: true,
		},
		{
			name: "multiple required keys all present",
			meta: common.RequiredMetadata{Keys: []string{"X-User-Sub", "X-Tenant-Id"}, Enabled: true},
			data: map[string]string{"X-User-Sub": "user-123", "X-Tenant-Id": "tenant-456"},
		},
		{
			name:    "multiple required keys one missing",
			meta:    common.RequiredMetadata{Keys: []string{"X-User-Sub", "X-Tenant-Id"}, Enabled: true},
			data:    map[string]string{"X-User-Sub": "user-123"},
			wantErr: true,
		},
		{
			name: "case insensitive HTTP header lookup",
			meta: common.RequiredMetadata{Keys: []string{"X-User-Sub"}, Enabled: true},
			data: map[string]string{"x-user-sub": "user-123"},
		},
		{
			name: "case insensitive mixed case",
			meta: common.RequiredMetadata{Keys: []string{"x-user-sub"}, Enabled: true},
			data: map[string]string{"X-User-Sub": "user-123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := &mapExtractor{data: tt.data, caseSensitive: false}
			err := tt.meta.Validate(ex)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, authly.ErrMissingRequiredMetadata) {
					t.Fatalf("expected ErrMissingRequiredMetadata, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestRequiredMetadataGRPCLowerCase(t *testing.T) {
	// gRPC metadata keys are always lower-case.
	meta := common.RequiredMetadata{Keys: []string{"x-user-sub"}, Enabled: true}
	ex := &mapExtractor{
		data:          map[string]string{"x-user-sub": "user-123"},
		caseSensitive: true, // gRPC-style: exact lower-case match
	}
	if err := meta.Validate(ex); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequiredMetadataGRPCMissing(t *testing.T) {
	meta := common.RequiredMetadata{Keys: []string{"x-user-sub"}, Enabled: true}
	ex := &mapExtractor{
		data:          map[string]string{},
		caseSensitive: true,
	}
	err := meta.Validate(ex)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, authly.ErrMissingRequiredMetadata) {
		t.Fatalf("expected ErrMissingRequiredMetadata, got %v", err)
	}
}

func TestExtractMetadataMap(t *testing.T) {
	meta := common.RequiredMetadata{Keys: []string{"X-User-Sub", "X-Tenant-Id"}, Enabled: true}
	ex := &mapExtractor{
		data:          map[string]string{"X-User-Sub": "user-123", "X-Tenant-Id": "tenant-456", "Other": "ignored"},
		caseSensitive: false,
	}
	m := meta.ExtractMetadataMap(ex)
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if m["x-user-sub"] != "user-123" {
		t.Fatalf("expected x-user-sub=user-123, got %s", m["x-user-sub"])
	}
	if m["x-tenant-id"] != "tenant-456" {
		t.Fatalf("expected x-tenant-id=tenant-456, got %s", m["x-tenant-id"])
	}
}

func TestExtractMetadataMapDisabled(t *testing.T) {
	meta := common.RequiredMetadata{Keys: []string{"X-User-Sub"}, Enabled: false}
	ex := &mapExtractor{data: map[string]string{"X-User-Sub": "user-123"}}
	m := meta.ExtractMetadataMap(ex)
	if m != nil {
		t.Fatalf("expected nil, got %v", m)
	}
}

func TestApplyMetadataToResult(t *testing.T) {
	t.Run("attaches metadata to result", func(t *testing.T) {
		result := &authly.Result{Claims: map[string]any{"sub": "user-123"}}
		meta := map[string]string{"x-user-sub": "user-123", "x-tenant-id": "tenant-456"}
		common.ApplyMetadataToResult(result, meta, true)

		metaVal, ok := result.Claims["_meta"]
		if !ok {
			t.Fatal("expected _meta in claims")
		}
		metaMap, ok := metaVal.(map[string]any)
		if !ok {
			t.Fatal("expected _meta to be map[string]any")
		}
		if metaMap["x-user-sub"] != "user-123" {
			t.Fatalf("expected x-user-sub=user-123, got %v", metaMap["x-user-sub"])
		}
		if metaMap["x-tenant-id"] != "tenant-456" {
			t.Fatalf("expected x-tenant-id=tenant-456, got %v", metaMap["x-tenant-id"])
		}
	})

	t.Run("does not attach when disabled", func(t *testing.T) {
		result := &authly.Result{Claims: map[string]any{"sub": "user-123"}}
		meta := map[string]string{"x-user-sub": "user-123"}
		common.ApplyMetadataToResult(result, meta, false)

		if _, ok := result.Claims["_meta"]; ok {
			t.Fatal("expected no _meta in claims when disabled")
		}
	})

	t.Run("handles nil result safely", func(t *testing.T) {
		// Should not panic.
		common.ApplyMetadataToResult(nil, map[string]string{"x": "y"}, true)
	})

	t.Run("handles empty meta safely", func(t *testing.T) {
		result := &authly.Result{Claims: map[string]any{}}
		common.ApplyMetadataToResult(result, nil, true)
		if _, ok := result.Claims["_meta"]; ok {
			t.Fatal("expected no _meta for empty meta map")
		}
	})

	t.Run("creates claims map if nil", func(t *testing.T) {
		result := &authly.Result{}
		meta := map[string]string{"x-user-sub": "user-123"}
		common.ApplyMetadataToResult(result, meta, true)
		if result.Claims == nil {
			t.Fatal("expected non-nil claims")
		}
		if _, ok := result.Claims["_meta"]; !ok {
			t.Fatal("expected _meta in claims")
		}
	})
}
