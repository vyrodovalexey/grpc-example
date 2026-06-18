// Package mtls_test provides unit tests for mTLS auth metric instrumentation.
package mtls_test

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
	"github.com/vyrodovalexey/grpc-example/internal/metrics"
)

func TestUnaryInterceptor_RecordsAuthMetric(t *testing.T) {
	tests := []struct {
		name       string
		ctx        context.Context
		wantResult string
	}{
		{
			name:       "success records mtls success metric",
			ctx:        createValidPeerContext(),
			wantResult: metrics.ResultSuccess,
		},
		{
			name:       "failure records mtls failure metric",
			ctx:        context.Background(),
			wantResult: metrics.ResultFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := zap.NewNop()
			interceptor := mtls.UnaryInterceptor(mtls.Config{}, logger)
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
			handler := func(_ context.Context, _ any) (any, error) {
				return "ok", nil
			}

			counter := metrics.AuthAttemptsTotal.WithLabelValues(metrics.AuthTypeMTLS, tt.wantResult)
			before := testutil.ToFloat64(counter)

			// Act
			_, _ = interceptor(tt.ctx, "request", info, handler)

			// Assert - the mTLS auth attempt counter for the expected outcome advanced.
			assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9)
		})
	}
}

func TestStreamInterceptor_RecordsAuthMetric(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	interceptor := mtls.StreamInterceptor(mtls.Config{}, logger)
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	stream := &mockServerStream{ctx: createValidPeerContext()}
	handler := func(_ any, _ grpc.ServerStream) error { return nil }

	counter := metrics.AuthAttemptsTotal.WithLabelValues(metrics.AuthTypeMTLS, metrics.ResultSuccess)
	before := testutil.ToFloat64(counter)

	// Act
	require.NoError(t, interceptor("server", stream, info, handler))

	// Assert
	assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9)
}
