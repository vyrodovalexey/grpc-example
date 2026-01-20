//go:build functional

// Package functional provides functional tests for the gRPC test server.
package functional

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	apiv1 "github.com/alexey/grpc-example/pkg/api/v1"
)

const (
	// testTimeout is the default timeout for test operations.
	testTimeout = 30 * time.Second

	// serverStartTimeout is the timeout for server startup.
	serverStartTimeout = 5 * time.Second
)

// testSuite holds the test infrastructure.
type testSuite struct {
	server     *grpc.Server
	client     apiv1.TestServiceClient
	conn       *grpc.ClientConn
	address    string
	cancelFunc context.CancelFunc
}

var suite *testSuite

// TestMain sets up and tears down the test infrastructure.
func TestMain(m *testing.M) {
	var err error
	suite, err = setupTestSuite()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup test suite: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	suite.teardown()
	os.Exit(code)
}

// setupTestSuite creates a new test suite with a running gRPC server.
func setupTestSuite() (*testSuite, error) {
	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %w", err)
	}
	address := listener.Addr().String()

	// Create logger (silent for tests)
	logger := zap.NewNop()

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register test service
	testService := newTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	serverErrCh := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	// Wait for server to be ready
	conn, err := waitForServer(ctx, address)
	if err != nil {
		cancel()
		grpcServer.Stop()
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	client := apiv1.NewTestServiceClient(conn)

	return &testSuite{
		server:     grpcServer,
		client:     client,
		conn:       conn,
		address:    address,
		cancelFunc: cancel,
	}, nil
}

// waitForServer waits for the gRPC server to be ready.
func waitForServer(ctx context.Context, address string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, serverStartTimeout)
	defer cancel()

	var conn *grpc.ClientConn
	var err error

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for server: %w", err)
		default:
			conn, err = grpc.NewClient(
				address,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err == nil {
				return conn, nil
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// teardown cleans up the test infrastructure.
func (s *testSuite) teardown() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.server != nil {
		s.server.GracefulStop()
	}
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
}

// getClient returns the test service client.
func getClient() apiv1.TestServiceClient {
	return suite.client
}

// getAddress returns the server address.
func getAddress() string {
	return suite.address
}

// newTestContext creates a new context with the default test timeout.
func newTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), testTimeout)
}
