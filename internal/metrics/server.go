package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	// readHeaderTimeout is the timeout for reading HTTP request headers.
	readHeaderTimeout = 10 * time.Second
	// shutdownTimeout is the timeout for graceful shutdown of the metrics server.
	shutdownTimeout = 5 * time.Second
)

// Server is an HTTP server that exposes Prometheus metrics and health endpoints.
type Server struct {
	httpServer *http.Server
	logger     *zap.Logger
}

// NewServer creates a new metrics HTTP server on the given port.
func NewServer(port int, logger *zap.Logger) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return &Server{
		httpServer: &http.Server{
			Addr:              fmt.Sprintf(":%d", port),
			Handler:           mux,
			ReadHeaderTimeout: readHeaderTimeout,
		},
		logger: logger.Named("metrics_server"),
	}
}

// Start starts the metrics HTTP server in a goroutine.
// It returns immediately. Use Shutdown to stop the server.
func (s *Server) Start() {
	go func() {
		s.logger.Info("starting metrics server", zap.String("address", s.httpServer.Addr))
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("metrics server error", zap.Error(err))
		}
	}()
}

// Shutdown gracefully shuts down the metrics HTTP server.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	s.logger.Info("shutting down metrics server")
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Error("metrics server shutdown error", zap.Error(err))
	}
}
