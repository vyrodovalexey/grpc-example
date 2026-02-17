// Package auth_test provides unit tests for the auth context functions.
package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
)

func TestWithIdentity_And_IdentityFromContext(t *testing.T) {
	tests := []struct {
		name     string
		identity *auth.Identity
		wantOK   bool
	}{
		{
			name: "store and retrieve identity",
			identity: &auth.Identity{
				Subject:    "user@example.com",
				Issuer:     "https://issuer.example.com",
				AuthMethod: "oidc",
				Claims:     map[string]string{"role": "admin"},
			},
			wantOK: true,
		},
		{
			name:     "store nil identity",
			identity: nil,
			wantOK:   true,
		},
		{
			name: "store identity with empty fields",
			identity: &auth.Identity{
				Subject:    "",
				Issuer:     "",
				AuthMethod: "",
				Claims:     nil,
			},
			wantOK: true,
		},
		{
			name: "store mtls identity",
			identity: &auth.Identity{
				Subject:    "cn=client",
				Issuer:     "cn=ca",
				AuthMethod: "mtls",
				Claims: map[string]string{
					"org":    "TestOrg",
					"ou":     "TestOU",
					"serial": "12345",
				},
			},
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			ctx := context.Background()

			// Act
			ctx = auth.WithIdentity(ctx, tt.identity)
			retrieved, ok := auth.IdentityFromContext(ctx)

			// Assert
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.identity, retrieved)
		})
	}
}

func TestIdentityFromContext_NoIdentity(t *testing.T) {
	// Arrange
	ctx := context.Background()

	// Act
	identity, ok := auth.IdentityFromContext(ctx)

	// Assert
	assert.False(t, ok)
	assert.Nil(t, identity)
}

func TestIdentityFromContext_WithOtherValues(t *testing.T) {
	// Arrange - context with other values but no identity
	type otherKey struct{}
	ctx := context.WithValue(context.Background(), otherKey{}, "some-value")

	// Act
	identity, ok := auth.IdentityFromContext(ctx)

	// Assert
	assert.False(t, ok)
	assert.Nil(t, identity)
}

func TestWithIdentity_OverwritesPrevious(t *testing.T) {
	// Arrange
	ctx := context.Background()
	first := &auth.Identity{Subject: "first", AuthMethod: "mtls"}
	second := &auth.Identity{Subject: "second", AuthMethod: "oidc"}

	// Act
	ctx = auth.WithIdentity(ctx, first)
	ctx = auth.WithIdentity(ctx, second)
	retrieved, ok := auth.IdentityFromContext(ctx)

	// Assert
	require.True(t, ok)
	assert.Equal(t, "second", retrieved.Subject)
	assert.Equal(t, "oidc", retrieved.AuthMethod)
}
