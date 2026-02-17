// Package mtls_test provides unit tests for the mtls interceptors.
package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
)

// mockServerStream implements grpc.ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockServerStream) SendHeader(metadata.MD) error { return nil }
func (m *mockServerStream) SetTrailer(metadata.MD)       {}
func (m *mockServerStream) SendMsg(any) error            { return nil }
func (m *mockServerStream) RecvMsg(any) error            { return nil }

// createValidPeerContext creates a context with valid mTLS peer info.
func createValidPeerContext() context.Context {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "test-client",
			Organization:       []string{"TestOrg"},
			OrganizationalUnit: []string{"Engineering"},
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		SerialNumber: big.NewInt(12345),
	}
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{
				{cert},
			},
		},
	}
	p := &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		AuthInfo: tlsInfo,
	}
	return peer.NewContext(context.Background(), p)
}

func TestUnaryInterceptor(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		cfg         mtls.Config
		wantErr     bool
		wantCode    codes.Code
		wantSubject string
	}{
		{
			name:        "successful authentication - no restrictions",
			ctx:         createValidPeerContext(),
			cfg:         mtls.Config{},
			wantErr:     false,
			wantSubject: "test-client",
		},
		{
			name: "successful authentication - allowed subject",
			ctx:  createValidPeerContext(),
			cfg: mtls.Config{
				AllowedSubjects: []string{"test-client"},
			},
			wantErr:     false,
			wantSubject: "test-client",
		},
		{
			name:     "failed authentication - no peer info",
			ctx:      context.Background(),
			cfg:      mtls.Config{},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
		{
			name: "failed authentication - subject not allowed",
			ctx:  createValidPeerContext(),
			cfg: mtls.Config{
				AllowedSubjects: []string{"other-client"},
			},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := zap.NewNop()
			interceptor := mtls.UnaryInterceptor(tt.cfg, logger)
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			handlerCalled := false
			handler := func(ctx context.Context, req any) (any, error) {
				handlerCalled = true
				// Verify identity is in context
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

func TestStreamInterceptor(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		cfg      mtls.Config
		wantErr  bool
		wantCode codes.Code
	}{
		{
			name:    "successful stream authentication",
			ctx:     createValidPeerContext(),
			cfg:     mtls.Config{},
			wantErr: false,
		},
		{
			name: "successful stream authentication - allowed subject",
			ctx:  createValidPeerContext(),
			cfg: mtls.Config{
				AllowedSubjects: []string{"test-client"},
			},
			wantErr: false,
		},
		{
			name:     "failed stream authentication - no peer info",
			ctx:      context.Background(),
			cfg:      mtls.Config{},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
		{
			name: "failed stream authentication - subject not allowed",
			ctx:  createValidPeerContext(),
			cfg: mtls.Config{
				AllowedSubjects: []string{"other-client"},
			},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := zap.NewNop()
			interceptor := mtls.StreamInterceptor(tt.cfg, logger)
			info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
			stream := &mockServerStream{ctx: tt.ctx}

			handlerCalled := false
			handler := func(srv any, ss grpc.ServerStream) error {
				handlerCalled = true
				// Verify identity is in the wrapped stream context
				identity, ok := auth.IdentityFromContext(ss.Context())
				require.True(t, ok)
				assert.Equal(t, "test-client", identity.Subject)
				assert.Equal(t, "mtls", identity.AuthMethod)
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

func TestUnaryInterceptor_HandlerError(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	interceptor := mtls.UnaryInterceptor(mtls.Config{}, logger)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := createValidPeerContext()

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

func TestStreamInterceptor_HandlerError(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	interceptor := mtls.StreamInterceptor(mtls.Config{}, logger)
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	stream := &mockServerStream{ctx: createValidPeerContext()}

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
