// Package oidc provides OIDC (OpenID Connect) authentication for gRPC servers.
package oidc

import "strings"

const (
	// AuthorizationKey is the gRPC metadata key for the authorization header.
	AuthorizationKey = "authorization"

	// BearerPrefix is the prefix for bearer tokens in the authorization header.
	BearerPrefix = "Bearer "
)

// ParseRequiredClaims parses a comma-separated string of key:value pairs into a map.
// Format: "scope:grpc:read,role:admin" -> {"scope": "grpc:read", "role": "admin"}
func ParseRequiredClaims(s string) map[string]string {
	result := make(map[string]string)
	if s == "" {
		return result
	}

	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		// Split on first colon only to support values containing colons.
		idx := strings.Index(pair, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(pair[:idx])
		value := strings.TrimSpace(pair[idx+1:])
		if key != "" {
			result[key] = value
		}
	}

	return result
}
