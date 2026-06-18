// Package oidc_test provides unit tests for OIDC auth metric instrumentation.
package oidc_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
	"github.com/vyrodovalexey/grpc-example/internal/metrics"
)

func TestOIDCUnaryInterceptor_RecordsAuthMetric(t *testing.T) {
	tests := []struct {
		name       string
		ctx        context.Context
		provider   oidc.Provider
		wantResult string
	}{
		{
			name:       "success records oidc success metric",
			ctx:        createOIDCIncomingContext("valid-token"),
			provider:   newValidMockProvider(),
			wantResult: metrics.ResultSuccess,
		},
		{
			name: "failure records oidc failure metric",
			ctx:  createOIDCIncomingContext("bad-token"),
			provider: &mockProvider{
				verifier: &mockTokenVerifier{err: fmt.Errorf("token expired")},
			},
			wantResult: metrics.ResultFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := zap.NewNop()
			interceptor := oidc.UnaryInterceptor(tt.provider, config.AuthConfig{}, logger)
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
			handler := func(_ context.Context, _ any) (any, error) {
				return "ok", nil
			}

			counter := metrics.AuthAttemptsTotal.WithLabelValues(metrics.AuthTypeOIDC, tt.wantResult)
			before := testutil.ToFloat64(counter)

			// Act
			_, _ = interceptor(tt.ctx, "request", info, handler)

			// Assert
			assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9)
		})
	}
}

func TestOIDCStreamInterceptor_RecordsAuthMetric(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	provider := newValidMockProvider()
	interceptor := oidc.StreamInterceptor(provider, config.AuthConfig{}, logger)
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
	stream := &oidcMockServerStream{ctx: createOIDCIncomingContext("valid-token")}
	handler := func(_ any, _ grpc.ServerStream) error { return nil }

	counter := metrics.AuthAttemptsTotal.WithLabelValues(metrics.AuthTypeOIDC, metrics.ResultSuccess)
	before := testutil.ToFloat64(counter)

	// Act
	require.NoError(t, interceptor("server", stream, info, handler))

	// Assert
	assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9)
}
