// Package auth_test provides unit tests for the auth package.
package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
)

func TestIdentity_String(t *testing.T) {
	tests := []struct {
		name     string
		identity *auth.Identity
		contains []string
	}{
		{
			name:     "nil identity",
			identity: nil,
			contains: []string{"Identity{nil}"},
		},
		{
			name: "identity without claims",
			identity: &auth.Identity{
				Subject:    "user@example.com",
				Issuer:     "https://issuer.example.com",
				AuthMethod: "oidc",
				Claims:     nil,
			},
			contains: []string{
				"Subject: user@example.com",
				"Issuer: https://issuer.example.com",
				"AuthMethod: oidc",
			},
		},
		{
			name: "identity with empty claims map",
			identity: &auth.Identity{
				Subject:    "cn=client",
				Issuer:     "cn=ca",
				AuthMethod: "mtls",
				Claims:     map[string]string{},
			},
			contains: []string{
				"Subject: cn=client",
				"Issuer: cn=ca",
				"AuthMethod: mtls",
			},
		},
		{
			name: "identity with claims",
			identity: &auth.Identity{
				Subject:    "user@example.com",
				Issuer:     "https://issuer.example.com",
				AuthMethod: "oidc",
				Claims: map[string]string{
					"role": "admin",
				},
			},
			contains: []string{
				"Subject: user@example.com",
				"Issuer: https://issuer.example.com",
				"AuthMethod: oidc",
				"Claims: {",
				"role: admin",
			},
		},
		{
			name: "identity with empty fields",
			identity: &auth.Identity{
				Subject:    "",
				Issuer:     "",
				AuthMethod: "",
				Claims:     nil,
			},
			contains: []string{
				"Identity{Subject: , Issuer: , AuthMethod: ",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result := tt.identity.String()

			// Assert
			for _, substr := range tt.contains {
				assert.Contains(t, result, substr)
			}
		})
	}
}

func TestIdentity_StringWithMultipleClaims(t *testing.T) {
	// Arrange
	identity := &auth.Identity{
		Subject:    "user",
		Issuer:     "issuer",
		AuthMethod: "oidc",
		Claims: map[string]string{
			"role":  "admin",
			"scope": "read",
		},
	}

	// Act
	result := identity.String()

	// Assert - both claims should be present (order may vary due to map iteration)
	assert.Contains(t, result, "role: admin")
	assert.Contains(t, result, "scope: read")
	assert.Contains(t, result, "Claims: {")
}
