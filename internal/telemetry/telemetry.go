// Package telemetry provides OpenTelemetry tracing initialization and shutdown.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap"
)

const (
	// tracerShutdownTimeout is the timeout for shutting down the tracer provider.
	tracerShutdownTimeout = 5 * time.Second
)

// Config holds the configuration for OpenTelemetry tracing.
type Config struct {
	Enabled     bool
	Endpoint    string
	ServiceName string
}

// tracerProvider holds the global tracer provider for shutdown.
var tracerProvider *sdktrace.TracerProvider

// InitTracer initializes the OpenTelemetry tracer provider.
// If the OTLP endpoint is not configured, a no-op tracer is used.
func InitTracer(ctx context.Context, cfg Config, logger *zap.Logger) error {
	log := logger.Named("telemetry")

	if !cfg.Enabled || cfg.Endpoint == "" {
		// No-op: OpenTelemetry is disabled or no endpoint configured.
		log.Info("OpenTelemetry tracing disabled (no endpoint configured)")
		return nil
	}

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(cfg.Endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "grpc-example-server"
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return fmt.Errorf("creating OTLP resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	// Support B3 and Jaeger propagation formats alongside W3C TraceContext and Baggage.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracerProvider = tp

	log.Info("OpenTelemetry tracing initialized",
		zap.String("endpoint", cfg.Endpoint),
		zap.String("service_name", serviceName),
	)

	return nil
}

// ShutdownTracer gracefully shuts down the tracer provider, flushing any remaining spans.
func ShutdownTracer(logger *zap.Logger) {
	if tracerProvider == nil {
		// No-op: tracer was never initialized.
		return
	}

	log := logger.Named("telemetry")
	ctx, cancel := context.WithTimeout(context.Background(), tracerShutdownTimeout)
	defer cancel()

	if err := tracerProvider.Shutdown(ctx); err != nil {
		log.Error("failed to shutdown tracer provider", zap.Error(err))
	} else {
		log.Info("tracer provider shut down successfully")
	}
}
