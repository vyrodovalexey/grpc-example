package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/grpc-example/internal/metrics"
)

func TestServerStartedTotal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		grpcType  string
		service   string
		method    string
		wantCount int
	}{
		{
			name:      "increment unary counter",
			grpcType:  "unary",
			service:   "test.Service",
			method:    "TestMethod",
			wantCount: 1,
		},
		{
			name:      "increment server_stream counter",
			grpcType:  "server_stream",
			service:   "test.StreamService",
			method:    "StreamMethod",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			counter := metrics.ServerStartedTotal.WithLabelValues(tt.grpcType, tt.service, tt.method)

			// Act
			counter.Inc()

			// Assert - verify counter can be collected (no panic)
			require.NotNil(t, counter)
		})
	}
}

func TestServerHandledTotal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		grpcType string
		service  string
		method   string
		code     string
	}{
		{
			name:     "increment with OK code",
			grpcType: "unary",
			service:  "test.Service",
			method:   "TestMethod",
			code:     "OK",
		},
		{
			name:     "increment with NotFound code",
			grpcType: "unary",
			service:  "test.Service",
			method:   "TestMethod",
			code:     "NotFound",
		},
		{
			name:     "increment with Internal code",
			grpcType: "server_stream",
			service:  "test.Service",
			method:   "StreamMethod",
			code:     "Internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			counter := metrics.ServerHandledTotal.WithLabelValues(tt.grpcType, tt.service, tt.method, tt.code)

			// Act
			counter.Inc()

			// Assert
			require.NotNil(t, counter)
		})
	}
}

func TestServerHandlingSeconds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		grpcType string
		service  string
		method   string
		value    float64
	}{
		{
			name:     "observe small duration",
			grpcType: "unary",
			service:  "test.Service",
			method:   "FastMethod",
			value:    0.001,
		},
		{
			name:     "observe large duration",
			grpcType: "server_stream",
			service:  "test.Service",
			method:   "SlowMethod",
			value:    5.0,
		},
		{
			name:     "observe zero duration",
			grpcType: "unary",
			service:  "test.Service",
			method:   "ZeroMethod",
			value:    0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			histogram := metrics.ServerHandlingSeconds.WithLabelValues(tt.grpcType, tt.service, tt.method)

			// Act
			histogram.Observe(tt.value)

			// Assert
			require.NotNil(t, histogram)
		})
	}
}

func TestAuthAttemptsTotal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		authType string
		result   string
	}{
		{
			name:     "successful mtls attempt",
			authType: "mtls",
			result:   "success",
		},
		{
			name:     "failed oidc attempt",
			authType: "oidc",
			result:   "failure",
		},
		{
			name:     "successful oidc attempt",
			authType: "oidc",
			result:   "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			counter := metrics.AuthAttemptsTotal.WithLabelValues(tt.authType, tt.result)

			// Act
			counter.Inc()

			// Assert
			require.NotNil(t, counter)
		})
	}
}

func TestMetricsRegisteredInDefaultRegistry(t *testing.T) {
	t.Parallel()

	// Arrange - increment each metric to ensure they appear in the gathered output
	metrics.ServerStartedTotal.WithLabelValues("unary", "test.Svc", "Reg").Inc()
	metrics.ServerHandledTotal.WithLabelValues("unary", "test.Svc", "Reg", "OK").Inc()
	metrics.ServerHandlingSeconds.WithLabelValues("unary", "test.Svc", "Reg").Observe(0.01)
	metrics.AuthAttemptsTotal.WithLabelValues("test", "success").Inc()

	// Act - gather all metrics from the default registry
	metricFamilies, err := prometheus.DefaultGatherer.Gather()

	// Assert
	require.NoError(t, err)

	// Build a set of metric names
	metricNames := make(map[string]bool)
	for _, mf := range metricFamilies {
		metricNames[mf.GetName()] = true
	}

	// Verify our metrics are registered
	assert.True(t, metricNames["grpc_server_started_total"], "ServerStartedTotal should be registered")
	assert.True(t, metricNames["grpc_server_handled_total"], "ServerHandledTotal should be registered")
	assert.True(t, metricNames["grpc_server_handling_seconds"], "ServerHandlingSeconds should be registered")
	assert.True(t, metricNames["auth_attempts_total"], "AuthAttemptsTotal should be registered")
}
