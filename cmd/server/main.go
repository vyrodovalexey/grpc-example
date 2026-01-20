// Package main provides the entry point for the gRPC test server.
package main

import (
	"context"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/config"
	"github.com/vyrodovalexey/grpc-example/internal/logger"
	"github.com/vyrodovalexey/grpc-example/internal/server"
	"github.com/vyrodovalexey/grpc-example/internal/service"
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
	log, err := logger.InitLogger(cfg.LogLevel)
	if err != nil {
		basicLogger, _ := zap.NewProduction()
		basicLogger.Fatal("failed to initialize logger", zap.Error(err))
	}
	defer logger.SyncLogger(log)

	log.Info("starting gRPC test server", zap.String("config", cfg.String()))

	// Create service
	testService := service.NewTestService(log)

	// Create server
	srv := server.NewServer(server.Config{
		Address:         cfg.GRPCAddress(),
		ShutdownTimeout: cfg.ShutdownTimeout,
	}, testService, log)

	// Setup signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start server
	if err := srv.Start(ctx); err != nil {
		log.Error("server error", zap.Error(err))
		cancel()
		return
	}

	log.Info("server shutdown complete")
}
