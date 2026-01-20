// Package server provides the gRPC server implementation with lifecycle management.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

// Server represents the gRPC server with lifecycle management.
type Server struct {
	grpcServer      *grpc.Server
	healthServer    *health.Server
	logger          *zap.Logger
	address         string
	shutdownTimeout time.Duration
}

// Config holds the server configuration.
type Config struct {
	Address         string
	ShutdownTimeout time.Duration
}

// NewServer creates a new gRPC server instance.
func NewServer(cfg Config, testService apiv1.TestServiceServer, logger *zap.Logger) *Server {
	grpcServer := grpc.NewServer()
	healthServer := health.NewServer()

	// Register services
	apiv1.RegisterTestServiceServer(grpcServer, testService)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	// Enable reflection for debugging
	reflection.Register(grpcServer)

	return &Server{
		grpcServer:      grpcServer,
		healthServer:    healthServer,
		logger:          logger.Named("grpc_server"),
		address:         cfg.Address,
		shutdownTimeout: cfg.ShutdownTimeout,
	}
}

// Start starts the gRPC server and blocks until it's stopped.
func (s *Server) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", s.address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.address, err)
	}

	s.logger.Info("starting gRPC server", zap.String("address", s.address))

	// Set health status to serving
	s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	s.healthServer.SetServingStatus(apiv1.TestService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			errCh <- fmt.Errorf("gRPC server error: %w", err)
		}
		close(errCh)
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("received shutdown signal")
		return s.gracefulShutdown()
	case err := <-errCh:
		if err != nil {
			return err
		}
		return nil
	}
}

// gracefulShutdown performs a graceful shutdown of the server.
func (s *Server) gracefulShutdown() error {
	s.logger.Info("initiating graceful shutdown", zap.Duration("timeout", s.shutdownTimeout))

	// Set health status to not serving
	s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	s.healthServer.SetServingStatus(apiv1.TestService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_NOT_SERVING)

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	// Channel to signal shutdown completion
	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-done:
		s.logger.Info("graceful shutdown completed")
		return nil
	case <-shutdownCtx.Done():
		s.logger.Warn("graceful shutdown timed out, forcing stop")
		s.grpcServer.Stop()
		return errors.New("graceful shutdown timed out")
	}
}

// Stop immediately stops the server.
func (s *Server) Stop() {
	s.logger.Info("stopping gRPC server immediately")
	s.grpcServer.Stop()
}
