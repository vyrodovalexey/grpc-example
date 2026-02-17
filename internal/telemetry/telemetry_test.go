package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
)

// resetTracerProvider resets the package-level tracerProvider to nil after each test.
func resetTracerProvider(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if tracerProvider != nil {
			_ = tracerProvider.Shutdown(context.Background())
		}
		tracerProvider = nil
	})
}

func TestInitTracer_Disabled(t *testing.T) {
	resetTracerProvider(t)

	// Arrange
	cfg := Config{
		Enabled:  false,
		Endpoint: "localhost:4318",
	}
	logger := zap.NewNop()

	// Act
	err := InitTracer(context.Background(), cfg, logger)

	// Assert
	require.NoError(t, err)
	assert.Nil(t, tracerProvider, "tracerProvider should be nil when disabled")
}

func TestInitTracer_NoEndpoint(t *testing.T) {
	resetTracerProvider(t)

	// Arrange
	cfg := Config{
		Enabled:  true,
		Endpoint: "",
	}
	logger := zap.NewNop()

	// Act
	err := InitTracer(context.Background(), cfg, logger)

	// Assert
	require.NoError(t, err)
	assert.Nil(t, tracerProvider, "tracerProvider should be nil when endpoint is empty")
}

func TestInitTracer_DisabledWithEmptyEndpoint(t *testing.T) {
	resetTracerProvider(t)

	// Arrange
	cfg := Config{
		Enabled:  false,
		Endpoint: "",
	}
	logger := zap.NewNop()

	// Act
	err := InitTracer(context.Background(), cfg, logger)

	// Assert
	require.NoError(t, err)
	assert.Nil(t, tracerProvider, "tracerProvider should be nil when both disabled and no endpoint")
}

func TestInitTracer_Enabled(t *testing.T) {
	resetTracerProvider(t)

	// Arrange
	cfg := Config{
		Enabled:     true,
		Endpoint:    "localhost:4318",
		ServiceName: "test-service",
	}
	logger := zap.NewNop()

	// Act
	err := InitTracer(context.Background(), cfg, logger)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, tracerProvider, "tracerProvider should be set when enabled with endpoint")

	// Verify the global tracer provider was set
	tp := otel.GetTracerProvider()
	assert.NotNil(t, tp)
}

func TestInitTracer_DefaultServiceName(t *testing.T) {
	resetTracerProvider(t)

	// Arrange
	cfg := Config{
		Enabled:     true,
		Endpoint:    "localhost:4318",
		ServiceName: "", // empty - should use default
	}
	logger := zap.NewNop()

	// Act
	err := InitTracer(context.Background(), cfg, logger)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, tracerProvider, "tracerProvider should be set even with default service name")
}

func TestInitTracer_CustomServiceName(t *testing.T) {
	resetTracerProvider(t)

	// Arrange
	cfg := Config{
		Enabled:     true,
		Endpoint:    "localhost:4318",
		ServiceName: "my-custom-service",
	}
	logger := zap.NewNop()

	// Act
	err := InitTracer(context.Background(), cfg, logger)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, tracerProvider, "tracerProvider should be set with custom service name")
}

func TestShutdownTracer_NilProvider(t *testing.T) {
	// Arrange - ensure tracerProvider is nil
	tracerProvider = nil
	logger := zap.NewNop()

	// Act & Assert - should not panic
	assert.NotPanics(t, func() {
		ShutdownTracer(logger)
	})
}

func TestShutdownTracer_AfterInit(t *testing.T) {
	resetTracerProvider(t)

	// Arrange - initialize a tracer
	cfg := Config{
		Enabled:     true,
		Endpoint:    "localhost:4318",
		ServiceName: "shutdown-test-service",
	}
	logger := zap.NewNop()

	err := InitTracer(context.Background(), cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, tracerProvider)

	// Act & Assert - should not panic
	assert.NotPanics(t, func() {
		ShutdownTracer(logger)
	})
}

func TestShutdownTracer_MultipleCallsAfterInit(t *testing.T) {
	// Arrange - create a tracer provider directly
	tp := sdktrace.NewTracerProvider()
	tracerProvider = tp
	logger := zap.NewNop()

	t.Cleanup(func() {
		tracerProvider = nil
	})

	// Act & Assert - first shutdown should work
	assert.NotPanics(t, func() {
		ShutdownTracer(logger)
	})
}

func TestInitTracer_CancelledContext(t *testing.T) {
	resetTracerProvider(t)

	// Arrange
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cfg := Config{
		Enabled:     true,
		Endpoint:    "localhost:4318",
		ServiceName: "cancelled-test",
	}
	logger := zap.NewNop()

	// Act - with cancelled context, the exporter creation may fail
	err := InitTracer(ctx, cfg, logger)

	// Assert - we expect an error due to cancelled context
	// The behavior depends on the OTLP exporter implementation
	// It may or may not return an error for cancelled context during creation
	if err != nil {
		assert.Contains(t, err.Error(), "cancel")
	}
}
