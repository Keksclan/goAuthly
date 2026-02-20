// Package common provides shared adapter utilities for goAuthly.
//
// Concurrency: All exported types and functions are safe for concurrent use.
package common

import (
	"fmt"
	"strings"

	"github.com/keksclan/goAuthly/authly"
)

// RequiredMetadata defines mandatory metadata keys that must be present
// in a request before authentication proceeds.
type RequiredMetadata struct {
	// Keys lists required metadata/header names.
	// For HTTP headers, comparison is case-insensitive.
	// For gRPC metadata, keys are treated as lower-case per gRPC conventions.
	Keys []string

	// Enabled controls whether metadata validation is active.
	// If false, Validate always returns nil.
	Enabled bool
}

// MetadataExtractor abstracts reading metadata from different transports.
type MetadataExtractor interface {
	// Get returns the value for the given key and whether it was found.
	Get(key string) (string, bool)
	// All returns all metadata key-value pairs.
	All() map[string]string
}

// Validate checks that all required keys are present and non-empty.
// Returns ErrMissingRequiredMetadata wrapping the missing key name on failure.
func (r RequiredMetadata) Validate(ex MetadataExtractor) error {
	if !r.Enabled || len(r.Keys) == 0 {
		return nil
	}
	for _, key := range r.Keys {
		val, ok := ex.Get(key)
		if !ok || strings.TrimSpace(val) == "" {
			return fmt.Errorf("%w: %s", authly.ErrMissingRequiredMetadata, key)
		}
	}
	return nil
}

// ExtractMetadataMap extracts the values of the required keys into a map.
// Only non-empty values are included. Keys are normalized to lower-case.
func (r RequiredMetadata) ExtractMetadataMap(ex MetadataExtractor) map[string]string {
	if !r.Enabled || len(r.Keys) == 0 {
		return nil
	}
	m := make(map[string]string, len(r.Keys))
	for _, key := range r.Keys {
		if val, ok := ex.Get(key); ok && strings.TrimSpace(val) != "" {
			m[strings.ToLower(key)] = val
		}
	}
	return m
}

// AdapterOptions holds common adapter configuration.
type AdapterOptions struct {
	RequiredMeta       RequiredMetadata
	AttachMetaToResult bool
}

// ApplyMetadataToResult merges extracted metadata into the Result.Claims
// under the "_meta" namespace if enabled.
func ApplyMetadataToResult(result *authly.Result, meta map[string]string, attach bool) {
	if !attach || result == nil || len(meta) == 0 {
		return
	}
	if result.Claims == nil {
		result.Claims = make(map[string]any)
	}
	metaMap := make(map[string]any, len(meta))
	for k, v := range meta {
		metaMap[k] = v
	}
	result.Claims["_meta"] = metaMap
}
