// Package auth_test provides unit tests for the auth stream wrapper.
package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
)

// streamMockServerStream implements grpc.ServerStream for testing AuthenticatedServerStream.
type streamMockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *streamMockServerStream) Context() context.Context {
	return m.ctx
}

func (m *streamMockServerStream) SetHeader(metadata.MD) error  { return nil }
func (m *streamMockServerStream) SendHeader(metadata.MD) error { return nil }
func (m *streamMockServerStream) SetTrailer(metadata.MD)       {}
func (m *streamMockServerStream) SendMsg(any) error            { return nil }
func (m *streamMockServerStream) RecvMsg(any) error            { return nil }

func TestAuthenticatedServerStream_Context(t *testing.T) {
	tests := []struct {
		name     string
		identity *auth.Identity
	}{
		{
			name: "returns enriched context with OIDC identity",
			identity: &auth.Identity{
				Subject:    "user@example.com",
				Issuer:     "https://issuer.example.com",
				AuthMethod: "oidc",
				Claims:     map[string]string{"role": "admin"},
			},
		},
		{
			name: "returns enriched context with mTLS identity",
			identity: &auth.Identity{
				Subject:    "cn=client",
				Issuer:     "cn=ca",
				AuthMethod: "mtls",
				Claims:     map[string]string{"org": "TestOrg"},
			},
		},
		{
			name: "returns enriched context with empty identity",
			identity: &auth.Identity{
				Subject:    "",
				Issuer:     "",
				AuthMethod: "",
				Claims:     nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			originalCtx := context.Background()
			enrichedCtx := auth.WithIdentity(originalCtx, tt.identity)
			innerStream := &streamMockServerStream{ctx: originalCtx}

			wrapped := auth.NewAuthenticatedServerStream(innerStream, enrichedCtx)

			// Act
			resultCtx := wrapped.Context()

			// Assert
			require.NotNil(t, resultCtx)
			identity, ok := auth.IdentityFromContext(resultCtx)
			require.True(t, ok)
			assert.Equal(t, tt.identity, identity)
		})
	}
}

func TestAuthenticatedServerStream_ContextOverridesInner(t *testing.T) {
	// Arrange - inner stream has a plain context, wrapped has enriched context
	originalCtx := context.Background()
	innerStream := &streamMockServerStream{ctx: originalCtx}

	identity := &auth.Identity{
		Subject:    "test-user",
		Issuer:     "test-issuer",
		AuthMethod: "oidc",
	}
	enrichedCtx := auth.WithIdentity(originalCtx, identity)

	wrapped := auth.NewAuthenticatedServerStream(innerStream, enrichedCtx)

	// Act
	wrappedCtx := wrapped.Context()
	innerCtx := innerStream.Context()

	// Assert - wrapped context has identity, inner does not
	wrappedIdentity, wrappedOK := auth.IdentityFromContext(wrappedCtx)
	require.True(t, wrappedOK)
	assert.Equal(t, "test-user", wrappedIdentity.Subject)

	innerIdentity, innerOK := auth.IdentityFromContext(innerCtx)
	assert.False(t, innerOK)
	assert.Nil(t, innerIdentity)
}

func TestAuthenticatedServerStream_DelegatesServerStreamMethods(t *testing.T) {
	// Arrange
	innerStream := &streamMockServerStream{ctx: context.Background()}
	wrapped := auth.NewAuthenticatedServerStream(innerStream, context.Background())

	// Act & Assert - verify that ServerStream methods are delegated
	assert.NoError(t, wrapped.SendMsg(nil))
	assert.NoError(t, wrapped.RecvMsg(nil))
	assert.NoError(t, wrapped.SetHeader(nil))
	assert.NoError(t, wrapped.SendHeader(nil))
	wrapped.SetTrailer(nil) // Should not panic
}
