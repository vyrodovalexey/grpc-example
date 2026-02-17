// Package oidc_test provides unit tests for the oidc config.
package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
)

func TestParseRequiredClaims(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "empty string",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "single claim",
			input: "role:admin",
			want:  map[string]string{"role": "admin"},
		},
		{
			name:  "multiple claims",
			input: "scope:grpc:read,role:admin",
			want: map[string]string{
				"scope": "grpc:read",
				"role":  "admin",
			},
		},
		{
			name:  "value with colons",
			input: "scope:grpc:read:write",
			want:  map[string]string{"scope": "grpc:read:write"},
		},
		{
			name:  "whitespace around key and value",
			input: " role : admin , scope : read ",
			want: map[string]string{
				"role":  "admin",
				"scope": "read",
			},
		},
		{
			name:  "entry without colon is skipped",
			input: "role:admin,invalid,scope:read",
			want: map[string]string{
				"role":  "admin",
				"scope": "read",
			},
		},
		{
			name:  "empty key is skipped",
			input: ":value,role:admin",
			want:  map[string]string{"role": "admin"},
		},
		{
			name:  "empty value is allowed",
			input: "role:",
			want:  map[string]string{"role": ""},
		},
		{
			name:  "single entry no colon",
			input: "invalid",
			want:  map[string]string{},
		},
		{
			name:  "multiple entries all without colons",
			input: "a,b,c",
			want:  map[string]string{},
		},
		{
			name:  "complex values with special characters",
			input: "aud:https://api.example.com,scope:openid profile email",
			want: map[string]string{
				"aud":   "https://api.example.com",
				"scope": "openid profile email",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result := oidc.ParseRequiredClaims(tt.input)

			// Assert
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify exported constants have expected values
	assert.Equal(t, "authorization", oidc.AuthorizationKey)
	assert.Equal(t, "Bearer ", oidc.BearerPrefix)
}
