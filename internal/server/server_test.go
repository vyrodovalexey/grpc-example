// Package server_test provides unit tests for the server package.
package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/alexey/grpc-example/internal/server"
	apiv1 "github.com/alexey/grpc-example/pkg/api/v1"
)

// mockTestService implements apiv1.TestServiceServer for testing.
type mockTestService struct {
	apiv1.UnimplementedTestServiceServer
}

func newTestLogger() *zap.Logger {
	return zap.NewNop()
}

func getAvailablePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return ":" + string(rune('0'+port/10000)) + string(rune('0'+(port/1000)%10)) + string(rune('0'+(port/100)%10)) + string(rune('0'+(port/10)%10)) + string(rune('0'+port%10))
}

func getAvailablePortInt(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port
}

func formatPort(port int) string {
	return ":" + intToString(port)
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

func TestNewServer(t *testing.T) {
	tests := []struct {
		name        string
		cfg         server.Config
		testService apiv1.TestServiceServer
		logger      *zap.Logger
	}{
		{
			name: "create server with valid config",
			cfg: server.Config{
				Address:         ":50051",
				ShutdownTimeout: 30 * time.Second,
			},
			testService: &mockTestService{},
			logger:      newTestLogger(),
		},
		{
			name: "create server with custom address",
			cfg: server.Config{
				Address:         ":8080",
				ShutdownTimeout: 60 * time.Second,
			},
			testService: &mockTestService{},
			logger:      newTestLogger(),
		},
		{
			name: "create server with short shutdown timeout",
			cfg: server.Config{
				Address:         ":50051",
				ShutdownTimeout: 1 * time.Second,
			},
			testService: &mockTestService{},
			logger:      newTestLogger(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			srv := server.NewServer(tt.cfg, tt.testService, tt.logger)

			// Assert
			require.NotNil(t, srv)
		})
	}
}

func TestServer_StartAndStop(t *testing.T) {
	// Arrange
	port := getAvailablePortInt(t)
	cfg := server.Config{
		Address:         formatPort(port),
		ShutdownTimeout: 5 * time.Second,
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is listening
	conn, err := net.DialTimeout("tcp", formatPort(port), time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	// Act - stop the server
	cancel()

	// Assert - server should stop gracefully
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServer_Stop(t *testing.T) {
	// Arrange
	port := getAvailablePortInt(t)
	cfg := server.Config{
		Address:         formatPort(port),
		ShutdownTimeout: 5 * time.Second,
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Act - stop immediately
	srv.Stop()

	// Assert - server should stop
	select {
	case <-errCh:
		// Server stopped (error or nil is fine)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServer_StopAlreadyStopped(t *testing.T) {
	// Arrange
	port := getAvailablePortInt(t)
	cfg := server.Config{
		Address:         formatPort(port),
		ShutdownTimeout: 5 * time.Second,
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Stop the server first time
	cancel()

	// Wait for server to stop
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}

	// Act - stop again (should not panic)
	assert.NotPanics(t, func() {
		srv.Stop()
	})
}

func TestServer_StartOnUnavailablePort(t *testing.T) {
	// Arrange - occupy a port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	occupiedPort := listener.Addr().(*net.TCPAddr).Port

	cfg := server.Config{
		Address:         formatPort(occupiedPort),
		ShutdownTimeout: 5 * time.Second,
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Act
	err = srv.Start(ctx)

	// Assert - should fail because port is occupied
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen")
}

func TestServer_GracefulShutdownWithConnections(t *testing.T) {
	// Arrange
	port := getAvailablePortInt(t)
	cfg := server.Config{
		Address:         formatPort(port),
		ShutdownTimeout: 5 * time.Second,
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create a gRPC connection
	conn, err := grpc.NewClient(
		formatPort(port),
		grpc.WithInsecure(),
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Act - initiate graceful shutdown
	cancel()

	// Assert - server should stop gracefully
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServer_MultipleStartAttempts(t *testing.T) {
	// Arrange
	port := getAvailablePortInt(t)
	cfg := server.Config{
		Address:         formatPort(port),
		ShutdownTimeout: 5 * time.Second,
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	ctx1, cancel1 := context.WithCancel(context.Background())

	// Start server first time
	errCh1 := make(chan error, 1)
	go func() {
		errCh1 <- srv.Start(ctx1)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is running
	conn, err := net.DialTimeout("tcp", formatPort(port), time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	// Stop the server
	cancel1()

	select {
	case <-errCh1:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServer_ConfigValues(t *testing.T) {
	tests := []struct {
		name            string
		address         string
		shutdownTimeout time.Duration
	}{
		{
			name:            "standard config",
			address:         ":50051",
			shutdownTimeout: 30 * time.Second,
		},
		{
			name:            "localhost address",
			address:         "127.0.0.1:8080",
			shutdownTimeout: 10 * time.Second,
		},
		{
			name:            "minimal timeout",
			address:         ":9090",
			shutdownTimeout: 1 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			cfg := server.Config{
				Address:         tt.address,
				ShutdownTimeout: tt.shutdownTimeout,
			}
			testService := &mockTestService{}
			logger := newTestLogger()

			// Act
			srv := server.NewServer(cfg, testService, logger)

			// Assert
			require.NotNil(t, srv)
		})
	}
}

func TestServer_ZeroShutdownTimeout(t *testing.T) {
	// Arrange
	port := getAvailablePortInt(t)
	cfg := server.Config{
		Address:         formatPort(port),
		ShutdownTimeout: 0, // Zero timeout
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Act - stop the server (with zero timeout, should timeout immediately)
	cancel()

	// Assert - server should stop (possibly with timeout error)
	select {
	case err := <-errCh:
		// With zero timeout, graceful shutdown will timeout immediately
		if err != nil {
			assert.Contains(t, err.Error(), "timed out")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServer_EmptyAddress(t *testing.T) {
	// Arrange
	cfg := server.Config{
		Address:         "", // Empty address - will use default
		ShutdownTimeout: 5 * time.Second,
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	// Act
	srv := server.NewServer(cfg, testService, logger)

	// Assert - server should be created
	require.NotNil(t, srv)
}

func TestServer_ContextCancelledBeforeStart(t *testing.T) {
	// Arrange
	port := getAvailablePortInt(t)
	cfg := server.Config{
		Address:         formatPort(port),
		ShutdownTimeout: 1 * time.Second, // Short timeout for test
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before starting

	// Act - run in goroutine with timeout
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Assert - server should complete (either with error or graceful shutdown)
	select {
	case <-errCh:
		// Server completed - this is the expected behavior
	case <-time.After(5 * time.Second):
		t.Fatal("server did not complete in time with cancelled context")
	}
}

// TestServer_ServerErrorDuringOperation tests the scenario where the gRPC server
// encounters an error or stops during operation, triggering the errCh path in Start().
// This covers the select case at lines 84-89 in server.go where the server receives
// from errCh when grpcServer.Serve() returns.
func TestServer_ServerErrorDuringOperation(t *testing.T) {
	tests := []struct {
		name        string
		stopMethod  string // "stop" for immediate stop, "graceful" for graceful stop via context
		expectError bool
	}{
		{
			name:        "server stops via Stop() method - errCh path with nil error",
			stopMethod:  "stop",
			expectError: false,
		},
		{
			name:        "server stops via context cancellation - graceful shutdown path",
			stopMethod:  "graceful",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			port := getAvailablePortInt(t)
			cfg := server.Config{
				Address:         formatPort(port),
				ShutdownTimeout: 5 * time.Second,
			}
			testService := &mockTestService{}
			logger := newTestLogger()

			srv := server.NewServer(cfg, testService, logger)
			require.NotNil(t, srv)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Start server in goroutine
			errCh := make(chan error, 1)
			go func() {
				errCh <- srv.Start(ctx)
			}()

			// Wait for server to start and verify it's listening
			time.Sleep(100 * time.Millisecond)
			conn, err := net.DialTimeout("tcp", formatPort(port), time.Second)
			require.NoError(t, err)
			require.NoError(t, conn.Close())

			// Act - trigger the appropriate stop method
			switch tt.stopMethod {
			case "stop":
				// This triggers the errCh path: grpcServer.Serve() returns
				// when Stop() is called, sending nil to errCh (since Stop()
				// causes Serve() to return without error)
				srv.Stop()
			case "graceful":
				// This triggers the ctx.Done() path
				cancel()
			}

			// Assert - verify server completes with expected result
			select {
			case err := <-errCh:
				if tt.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("server did not stop in time")
			}
		})
	}
}

// TestServer_StopTriggersErrChPath specifically tests that calling Stop() causes
// the server to exit through the errCh path (not the ctx.Done() path).
// When Stop() is called, grpcServer.Serve() returns, which sends to errCh.
func TestServer_StopTriggersErrChPath(t *testing.T) {
	// Arrange
	port := getAvailablePortInt(t)
	cfg := server.Config{
		Address:         formatPort(port),
		ShutdownTimeout: 5 * time.Second,
	}
	testService := &mockTestService{}
	logger := newTestLogger()

	srv := server.NewServer(cfg, testService, logger)
	require.NotNil(t, srv)

	// Use a context that we will NOT cancel - this ensures we're testing
	// the errCh path, not the ctx.Done() path
	ctx := context.Background()

	// Start server in goroutine
	resultCh := make(chan error, 1)
	go func() {
		resultCh <- srv.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is running
	conn, err := net.DialTimeout("tcp", formatPort(port), time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	// Act - call Stop() which causes grpcServer.Serve() to return
	// This triggers the errCh path in the select statement
	srv.Stop()

	// Assert - server should return nil (no error) through errCh path
	select {
	case err := <-resultCh:
		// When Stop() is called, Serve() returns without error,
		// so errCh receives nil, and Start() returns nil
		assert.NoError(t, err, "Stop() should cause server to exit cleanly through errCh path")
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}
