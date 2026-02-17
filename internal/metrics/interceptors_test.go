package metrics_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/grpc-example/internal/metrics"
)

func TestSplitMethodName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		fullMethod  string
		wantService string
		wantMethod  string
	}{
		{
			name:        "standard gRPC method format",
			fullMethod:  "/package.service/method",
			wantService: "package.service",
			wantMethod:  "method",
		},
		{
			name:        "unknown format without slash",
			fullMethod:  "unknown",
			wantService: "unknown",
			wantMethod:  "unknown",
		},
		{
			name:        "simple service/method format",
			fullMethod:  "/service/method",
			wantService: "service",
			wantMethod:  "method",
		},
		{
			name:        "empty string",
			fullMethod:  "",
			wantService: "unknown",
			wantMethod:  "",
		},
		{
			name:        "nested package format",
			fullMethod:  "/com.example.api.v1.TestService/GetItem",
			wantService: "com.example.api.v1.TestService",
			wantMethod:  "GetItem",
		},
		{
			name:        "method with multiple slashes",
			fullMethod:  "/a/b/c",
			wantService: "a/b",
			wantMethod:  "c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Act
			interceptor := metrics.UnaryServerInterceptor()

			// We need to test splitMethodName indirectly through the interceptor
			// by checking that the interceptor doesn't panic with various method names
			info := &grpc.UnaryServerInfo{
				FullMethod: tt.fullMethod,
			}

			handler := func(_ context.Context, _ any) (any, error) {
				return "response", nil
			}

			// Act - the interceptor internally calls splitMethodName
			resp, err := interceptor(context.Background(), nil, info, handler)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, "response", resp)
		})
	}
}

func TestUnaryServerInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		fullMethod  string
		handlerResp any
		handlerErr  error
		wantResp    any
		wantErr     bool
		wantCode    codes.Code
	}{
		{
			name:        "successful handler - OK code",
			fullMethod:  "/test.Service/TestMethod",
			handlerResp: "success",
			handlerErr:  nil,
			wantResp:    "success",
			wantErr:     false,
			wantCode:    codes.OK,
		},
		{
			name:        "handler returns error - NotFound",
			fullMethod:  "/test.Service/TestMethod",
			handlerResp: nil,
			handlerErr:  status.Error(codes.NotFound, "not found"),
			wantResp:    nil,
			wantErr:     true,
			wantCode:    codes.NotFound,
		},
		{
			name:        "handler returns error - Internal",
			fullMethod:  "/test.Service/InternalMethod",
			handlerResp: nil,
			handlerErr:  status.Error(codes.Internal, "internal error"),
			wantResp:    nil,
			wantErr:     true,
			wantCode:    codes.Internal,
		},
		{
			name:        "handler returns non-gRPC error",
			fullMethod:  "/test.Service/ErrorMethod",
			handlerResp: nil,
			handlerErr:  errors.New("plain error"),
			wantResp:    nil,
			wantErr:     true,
			wantCode:    codes.Unknown,
		},
		{
			name:        "handler returns response with nil error",
			fullMethod:  "/test.Service/NilMethod",
			handlerResp: map[string]string{"key": "value"},
			handlerErr:  nil,
			wantResp:    map[string]string{"key": "value"},
			wantErr:     false,
			wantCode:    codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			interceptor := metrics.UnaryServerInterceptor()
			info := &grpc.UnaryServerInfo{
				FullMethod: tt.fullMethod,
			}

			handler := func(_ context.Context, _ any) (any, error) {
				return tt.handlerResp, tt.handlerErr
			}

			// Act
			resp, err := interceptor(context.Background(), nil, info, handler)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, status.Code(err))
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantResp, resp)
		})
	}
}

func TestUnaryServerInterceptor_PassesThroughContext(t *testing.T) {
	t.Parallel()

	// Arrange
	type ctxKey string
	key := ctxKey("test-key")
	ctx := context.WithValue(context.Background(), key, "test-value")

	interceptor := metrics.UnaryServerInterceptor()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/TestMethod",
	}

	var capturedCtx context.Context
	handler := func(ctx context.Context, _ any) (any, error) {
		capturedCtx = ctx
		return "ok", nil
	}

	// Act
	_, err := interceptor(ctx, nil, info, handler)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "test-value", capturedCtx.Value(key))
}

func TestUnaryServerInterceptor_PassesThroughRequest(t *testing.T) {
	t.Parallel()

	// Arrange
	interceptor := metrics.UnaryServerInterceptor()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/TestMethod",
	}

	testReq := "test-request"
	var capturedReq any
	handler := func(_ context.Context, req any) (any, error) {
		capturedReq = req
		return "ok", nil
	}

	// Act
	_, err := interceptor(context.Background(), testReq, info, handler)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, testReq, capturedReq)
}

// mockServerStream implements grpc.ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func TestStreamServerInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		fullMethod     string
		isClientStream bool
		handlerErr     error
		wantErr        bool
		wantGRPCType   string
	}{
		{
			name:           "server_stream - successful handler",
			fullMethod:     "/test.Service/ServerStreamMethod",
			isClientStream: false,
			handlerErr:     nil,
			wantErr:        false,
			wantGRPCType:   "server_stream",
		},
		{
			name:           "bidi_stream - successful handler",
			fullMethod:     "/test.Service/BidiStreamMethod",
			isClientStream: true,
			handlerErr:     nil,
			wantErr:        false,
			wantGRPCType:   "bidi_stream",
		},
		{
			name:           "server_stream - handler returns error",
			fullMethod:     "/test.Service/ErrorStreamMethod",
			isClientStream: false,
			handlerErr:     status.Error(codes.Internal, "stream error"),
			wantErr:        true,
			wantGRPCType:   "server_stream",
		},
		{
			name:           "bidi_stream - handler returns error",
			fullMethod:     "/test.Service/ErrorBidiMethod",
			isClientStream: true,
			handlerErr:     status.Error(codes.Unavailable, "unavailable"),
			wantErr:        true,
			wantGRPCType:   "bidi_stream",
		},
		{
			name:           "server_stream - handler returns non-gRPC error",
			fullMethod:     "/test.Service/PlainErrorMethod",
			isClientStream: false,
			handlerErr:     errors.New("plain stream error"),
			wantErr:        true,
			wantGRPCType:   "server_stream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			interceptor := metrics.StreamServerInterceptor()
			info := &grpc.StreamServerInfo{
				FullMethod:     tt.fullMethod,
				IsClientStream: tt.isClientStream,
				IsServerStream: !tt.isClientStream,
			}

			stream := &mockServerStream{ctx: context.Background()}

			handler := func(_ any, _ grpc.ServerStream) error {
				return tt.handlerErr
			}

			// Act
			err := interceptor(nil, stream, info, handler)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.handlerErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestStreamServerInterceptor_PassesThroughServerAndStream(t *testing.T) {
	t.Parallel()

	// Arrange
	interceptor := metrics.StreamServerInterceptor()
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test.Service/StreamMethod",
		IsClientStream: false,
		IsServerStream: true,
	}

	testSrv := "test-server"
	stream := &mockServerStream{ctx: context.Background()}

	var capturedSrv any
	var capturedStream grpc.ServerStream
	handler := func(srv any, ss grpc.ServerStream) error {
		capturedSrv = srv
		capturedStream = ss
		return nil
	}

	// Act
	err := interceptor(testSrv, stream, info, handler)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, testSrv, capturedSrv)
	assert.Equal(t, stream, capturedStream)
}
