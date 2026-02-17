// Package oidc_test provides unit tests for the oidc interceptors.
package oidc_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
	"github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
)

// oidcMockServerStream implements grpc.ServerStream for testing.
type oidcMockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *oidcMockServerStream) Context() context.Context {
	return m.ctx
}

func (m *oidcMockServerStream) SetHeader(grpcmd.MD) error  { return nil }
func (m *oidcMockServerStream) SendHeader(grpcmd.MD) error { return nil }
func (m *oidcMockServerStream) SetTrailer(grpcmd.MD)       {}
func (m *oidcMockServerStream) SendMsg(any) error          { return nil }
func (m *oidcMockServerStream) RecvMsg(any) error          { return nil }

// createOIDCIncomingContext creates a context with a Bearer token in gRPC metadata.
func createOIDCIncomingContext(token string) context.Context {
	md := grpcmd.New(map[string]string{"authorization": "Bearer " + token})
	return grpcmd.NewIncomingContext(context.Background(), md)
}

// newValidMockProvider creates a mock provider that returns a valid token with claims.
func newValidMockProvider() oidc.Provider {
	return &mockProvider{
		verifier: &mockTokenVerifier{
			token: createIDTokenWithClaims(
				"https://issuer.example.com",
				"user@example.com",
				[]string{"test-client"},
				`{"sub":"user@example.com","iss":"https://issuer.example.com"}`,
			),
		},
	}
}

func TestOIDCUnaryInterceptor(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		provider    oidc.Provider
		cfg         config.AuthConfig
		wantErr     bool
		wantCode    codes.Code
		wantSubject string
	}{
		{
			name:        "successful authentication",
			ctx:         createOIDCIncomingContext("valid-token"),
			provider:    newValidMockProvider(),
			cfg:         config.AuthConfig{},
			wantErr:     false,
			wantSubject: "user@example.com",
		},
		{
			name:     "failed authentication - no metadata",
			ctx:      context.Background(),
			provider: &mockProvider{verifier: &mockTokenVerifier{}},
			cfg:      config.AuthConfig{},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
		{
			name: "failed authentication - token verification error",
			ctx:  createOIDCIncomingContext("invalid-token"),
			provider: &mockProvider{
				verifier: &mockTokenVerifier{
					err: fmt.Errorf("token expired"),
				},
			},
			cfg:      config.AuthConfig{},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := zap.NewNop()
			interceptor := oidc.UnaryInterceptor(tt.provider, tt.cfg, logger)
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			handlerCalled := false
			handler := func(ctx context.Context, req any) (any, error) {
				handlerCalled = true
				identity, ok := auth.IdentityFromContext(ctx)
				require.True(t, ok)
				assert.Equal(t, tt.wantSubject, identity.Subject)
				return "response", nil
			}

			// Act
			resp, err := interceptor(tt.ctx, "request", info, handler)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
				assert.False(t, handlerCalled)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				assert.True(t, handlerCalled)
				assert.Equal(t, "response", resp)
			}
		})
	}
}

func TestOIDCStreamInterceptor(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		provider oidc.Provider
		cfg      config.AuthConfig
		wantErr  bool
		wantCode codes.Code
	}{
		{
			name:     "successful stream authentication",
			ctx:      createOIDCIncomingContext("valid-token"),
			provider: newValidMockProvider(),
			cfg:      config.AuthConfig{},
			wantErr:  false,
		},
		{
			name:     "failed stream authentication - no metadata",
			ctx:      context.Background(),
			provider: &mockProvider{verifier: &mockTokenVerifier{}},
			cfg:      config.AuthConfig{},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
		{
			name: "failed stream authentication - token error",
			ctx:  createOIDCIncomingContext("bad-token"),
			provider: &mockProvider{
				verifier: &mockTokenVerifier{
					err: fmt.Errorf("invalid signature"),
				},
			},
			cfg:      config.AuthConfig{},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := zap.NewNop()
			interceptor := oidc.StreamInterceptor(tt.provider, tt.cfg, logger)
			info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
			stream := &oidcMockServerStream{ctx: tt.ctx}

			handlerCalled := false
			handler := func(srv any, ss grpc.ServerStream) error {
				handlerCalled = true
				identity, ok := auth.IdentityFromContext(ss.Context())
				require.True(t, ok)
				assert.Equal(t, "user@example.com", identity.Subject)
				assert.Equal(t, "oidc", identity.AuthMethod)
				return nil
			}

			// Act
			err := interceptor("server", stream, info, handler)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
				assert.False(t, handlerCalled)
			} else {
				require.NoError(t, err)
				assert.True(t, handlerCalled)
			}
		})
	}
}

func TestOIDCUnaryInterceptor_HandlerError(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	provider := newValidMockProvider()
	interceptor := oidc.UnaryInterceptor(provider, config.AuthConfig{}, logger)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := createOIDCIncomingContext("valid-token")

	handler := func(ctx context.Context, req any) (any, error) {
		return nil, status.Error(codes.Internal, "handler error")
	}

	// Act
	resp, err := interceptor(ctx, "request", info, handler)

	// Assert
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Nil(t, resp)
}

func TestOIDCStreamInterceptor_HandlerError(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	provider := newValidMockProvider()
	interceptor := oidc.StreamInterceptor(provider, config.AuthConfig{}, logger)
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	stream := &oidcMockServerStream{ctx: createOIDCIncomingContext("valid-token")}

	handler := func(srv any, ss grpc.ServerStream) error {
		return status.Error(codes.Internal, "stream handler error")
	}

	// Act
	err := interceptor("server", stream, info, handler)

	// Assert
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// Test that the authenticatedServerStream wraps context correctly.
func TestOIDCStreamInterceptor_WrappedStreamContext(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	provider := newValidMockProvider()
	interceptor := oidc.StreamInterceptor(provider, config.AuthConfig{}, logger)
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	originalCtx := createOIDCIncomingContext("valid-token")
	stream := &oidcMockServerStream{ctx: originalCtx}

	// Act
	var wrappedCtx context.Context
	handler := func(srv any, ss grpc.ServerStream) error {
		wrappedCtx = ss.Context()
		return nil
	}
	err := interceptor("server", stream, info, handler)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, wrappedCtx)
	identity, ok := auth.IdentityFromContext(wrappedCtx)
	require.True(t, ok)
	assert.Equal(t, "user@example.com", identity.Subject)
}

// Test with a nil verifier token (edge case).
func TestOIDCUnaryInterceptor_NilToken(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	provider := &mockProvider{
		verifier: &mockTokenVerifier{
			token: nil,
			err:   fmt.Errorf("verification failed"),
		},
	}
	interceptor := oidc.UnaryInterceptor(provider, config.AuthConfig{}, logger)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := createOIDCIncomingContext("some-token")

	handler := func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	// Act
	resp, err := interceptor(ctx, "request", info, handler)

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

// Test with audience configured and matching.
func TestOIDCUnaryInterceptor_WithAudience(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	token := createIDTokenWithClaims(
		"https://issuer.example.com",
		"user@example.com",
		[]string{"my-api", "other-api"},
		`{"sub":"user@example.com"}`,
	)
	provider := &mockProvider{
		verifier: &mockTokenVerifier{token: token},
	}
	cfg := config.AuthConfig{
		OIDCAudience: "my-api",
	}
	interceptor := oidc.UnaryInterceptor(provider, cfg, logger)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := createOIDCIncomingContext("valid-token")

	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return "ok", nil
	}

	// Act
	resp, err := interceptor(ctx, "request", info, handler)

	// Assert
	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "ok", resp)
}

// Test with audience configured but not matching.
func TestOIDCUnaryInterceptor_AudienceMismatch(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	token := createIDTokenWithClaims(
		"https://issuer.example.com",
		"user@example.com",
		[]string{"other-api"},
		`{"sub":"user@example.com"}`,
	)
	provider := &mockProvider{
		verifier: &mockTokenVerifier{token: token},
	}
	cfg := config.AuthConfig{
		OIDCAudience: "my-api",
	}
	interceptor := oidc.UnaryInterceptor(provider, cfg, logger)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := createOIDCIncomingContext("valid-token")

	handler := func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	}

	// Act
	resp, err := interceptor(ctx, "request", info, handler)

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}
