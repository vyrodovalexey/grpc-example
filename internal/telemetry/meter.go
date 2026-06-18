// Package telemetry provides OpenTelemetry tracing and metrics initialization and shutdown.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap"
)

const (
	// meterShutdownTimeout is the timeout for shutting down the meter provider.
	meterShutdownTimeout = 5 * time.Second
	// meterExportInterval is the periodic export interval for the OTLP metric reader.
	meterExportInterval = 15 * time.Second
)

// meterProvider holds the global OTLP meter provider for shutdown.
//
// It is intentionally separate from the Prometheus default registry: the Prometheus
// pull endpoint (/metrics) remains the authoritative source of truth, and this OTLP
// push pipeline is purely additive and gated by the OTEL configuration.
var meterProvider *sdkmetric.MeterProvider

// InitMeterProvider initializes the OpenTelemetry OTLP metrics pipeline.
//
// When OpenTelemetry is disabled or no endpoint is configured the function is a no-op
// and returns nil, leaving the global meter provider untouched. The created provider
// uses a dedicated SDK meter provider and never touches the Prometheus default registry,
// so the Prometheus /metrics endpoint stays authoritative.
func InitMeterProvider(ctx context.Context, cfg Config, logger *zap.Logger) error {
	log := logger.Named("telemetry")

	if !cfg.Enabled || cfg.Endpoint == "" {
		// No-op: OpenTelemetry metrics export is disabled or no endpoint configured.
		log.Info("OpenTelemetry metrics export disabled (no endpoint configured)")
		return nil
	}

	exporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(cfg.Endpoint),
		otlpmetrichttp.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("creating OTLP metric exporter: %w", err)
	}

	serviceName := resolveServiceName(cfg.ServiceName)

	res, err := buildResource(ctx, serviceName)
	if err != nil {
		return err
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(meterExportInterval),
	)

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	)

	otel.SetMeterProvider(mp)
	meterProvider = mp

	log.Info("OpenTelemetry metrics export initialized",
		zap.String("endpoint", cfg.Endpoint),
		zap.String("service_name", serviceName),
		zap.Duration("export_interval", meterExportInterval),
	)

	return nil
}

// ShutdownMeterProvider gracefully shuts down the meter provider, flushing any buffered metrics.
// It is a no-op when the meter provider was never initialized.
func ShutdownMeterProvider(logger *zap.Logger) {
	if meterProvider == nil {
		// No-op: meter provider was never initialized.
		return
	}

	log := logger.Named("telemetry")
	ctx, cancel := context.WithTimeout(context.Background(), meterShutdownTimeout)
	defer cancel()

	if err := meterProvider.Shutdown(ctx); err != nil {
		log.Error("failed to shutdown meter provider", zap.Error(err))
	} else {
		log.Info("meter provider shut down successfully")
	}

	meterProvider = nil
}
