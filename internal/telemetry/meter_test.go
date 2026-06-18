package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap"
)

// resetMeterProvider resets the package-level meterProvider to nil after each test
// so global state does not leak between tests.
func resetMeterProvider(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if meterProvider != nil {
			_ = meterProvider.Shutdown(context.Background())
		}
		meterProvider = nil
	})
}

func TestInitMeterProvider_Disabled(t *testing.T) {
	resetMeterProvider(t)

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "disabled with endpoint",
			cfg:  Config{Enabled: false, Endpoint: "localhost:4318"},
		},
		{
			name: "enabled without endpoint",
			cfg:  Config{Enabled: true, Endpoint: ""},
		},
		{
			name: "disabled without endpoint",
			cfg:  Config{Enabled: false, Endpoint: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			meterProvider = nil
			logger := zap.NewNop()

			// Act
			err := InitMeterProvider(context.Background(), tt.cfg, logger)

			// Assert - disabled config is a strict no-op.
			require.NoError(t, err)
			assert.Nil(t, meterProvider, "meterProvider should remain nil when disabled or no endpoint")
		})
	}
}

func TestInitMeterProvider_Enabled(t *testing.T) {
	resetMeterProvider(t)

	tests := []struct {
		name        string
		serviceName string
	}{
		{
			name:        "custom service name",
			serviceName: "metrics-test-service",
		},
		{
			name:        "default service name",
			serviceName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			resetMeterProvider(t)
			meterProvider = nil
			cfg := Config{
				Enabled:     true,
				Endpoint:    "localhost:4318",
				ServiceName: tt.serviceName,
			}
			logger := zap.NewNop()

			// Act
			err := InitMeterProvider(context.Background(), cfg, logger)

			// Assert - the OTLP HTTP exporter is created lazily and does not dial
			// at construction time, so initialization succeeds without a collector.
			require.NoError(t, err)
			assert.NotNil(t, meterProvider, "meterProvider should be set when enabled with endpoint")
		})
	}
}

func TestShutdownMeterProvider_NilProvider(t *testing.T) {
	// Arrange
	meterProvider = nil
	logger := zap.NewNop()

	// Act & Assert - shutting down without init is a no-op and must not panic.
	assert.NotPanics(t, func() {
		ShutdownMeterProvider(logger)
	})
	assert.Nil(t, meterProvider)
}

func TestShutdownMeterProvider_AfterInit(t *testing.T) {
	resetMeterProvider(t)

	// Arrange
	cfg := Config{
		Enabled:     true,
		Endpoint:    "localhost:4318",
		ServiceName: "shutdown-meter-service",
	}
	logger := zap.NewNop()
	require.NoError(t, InitMeterProvider(context.Background(), cfg, logger))
	require.NotNil(t, meterProvider)

	// Act & Assert - shutdown succeeds and clears the provider.
	assert.NotPanics(t, func() {
		ShutdownMeterProvider(logger)
	})
	assert.Nil(t, meterProvider, "meterProvider should be nil after shutdown")
}

func TestShutdownMeterProvider_Idempotent(t *testing.T) {
	// Arrange - create a provider directly so we control its lifecycle.
	mp := sdkmetric.NewMeterProvider()
	meterProvider = mp
	logger := zap.NewNop()
	t.Cleanup(func() { meterProvider = nil })

	// Act & Assert - first shutdown clears the provider; subsequent shutdowns are
	// safe no-ops (idempotent).
	assert.NotPanics(t, func() {
		ShutdownMeterProvider(logger)
		ShutdownMeterProvider(logger)
		ShutdownMeterProvider(logger)
	})
	assert.Nil(t, meterProvider)
}

func TestInitMeterProvider_CancelledContext(t *testing.T) {
	resetMeterProvider(t)

	// Arrange
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := Config{
		Enabled:     true,
		Endpoint:    "localhost:4318",
		ServiceName: "cancelled-meter-test",
	}
	logger := zap.NewNop()

	// Act - exporter/resource construction may or may not observe the cancelled
	// context depending on the SDK; either way the call must not panic.
	err := InitMeterProvider(ctx, cfg, logger)

	// Assert
	if err != nil {
		assert.Contains(t, err.Error(), "cancel")
	}
}
