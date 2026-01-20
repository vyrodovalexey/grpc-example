// Package main provides the entry point for the gRPC test server.
package main

import (
	"context"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/alexey/grpc-example/internal/config"
	"github.com/alexey/grpc-example/internal/server"
	"github.com/alexey/grpc-example/internal/service"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		// Use basic logger for startup errors
		basicLogger, _ := zap.NewProduction()
		basicLogger.Fatal("failed to load configuration", zap.Error(err))
	}

	// Initialize logger
	logger, err := initLogger(cfg.LogLevel)
	if err != nil {
		basicLogger, _ := zap.NewProduction()
		basicLogger.Fatal("failed to initialize logger", zap.Error(err))
	}
	defer syncLogger(logger)

	logger.Info("starting gRPC test server", zap.String("config", cfg.String()))

	// Create service
	testService := service.NewTestService(logger)

	// Create server
	srv := server.NewServer(server.Config{
		Address:         cfg.GRPCAddress(),
		ShutdownTimeout: cfg.ShutdownTimeout,
	}, testService, logger)

	// Setup signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start server
	if err := srv.Start(ctx); err != nil {
		logger.Error("server error", zap.Error(err))
		cancel()
		return
	}

	logger.Info("server shutdown complete")
}

// initLogger initializes the zap logger with the specified log level.
func initLogger(level string) (*zap.Logger, error) {
	zapLevel, err := parseLogLevel(level)
	if err != nil {
		return nil, err
	}

	zapConfig := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding: "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return zapConfig.Build()
}

// parseLogLevel converts a string log level to zapcore.Level.
func parseLogLevel(level string) (zapcore.Level, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		return zapcore.InfoLevel, err
	}
	return zapLevel, nil
}

// syncLogger flushes any buffered log entries.
func syncLogger(logger *zap.Logger) {
	if err := logger.Sync(); err != nil {
		// Ignore sync errors for stdout/stderr on some platforms
		return
	}
}
