package metrics_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/metrics"
)

// getFreePort returns a free TCP port for testing.
func getFreePort(t *testing.T) int {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())

	return port
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		port   int
		logger *zap.Logger
	}{
		{
			name:   "valid port and logger",
			port:   9090,
			logger: zap.NewNop(),
		},
		{
			name:   "different port",
			port:   8080,
			logger: zap.NewNop(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Act
			server := metrics.NewServer(tt.port, tt.logger)

			// Assert
			require.NotNil(t, server)
		})
	}
}

func TestServer_StartAndShutdown(t *testing.T) {
	// Arrange
	port := getFreePort(t)
	logger := zap.NewNop()
	server := metrics.NewServer(port, logger)

	// Act - start the server
	server.Start()

	// Give the server time to start
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 3*time.Second, 100*time.Millisecond, "server should be listening")

	// Act - shutdown the server
	server.Shutdown()

	// Assert - server should no longer accept connections
	time.Sleep(100 * time.Millisecond)
	_, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	assert.Error(t, err, "server should not accept connections after shutdown")
}

func TestServer_MetricsEndpoint(t *testing.T) {
	// Arrange
	port := getFreePort(t)
	logger := zap.NewNop()
	server := metrics.NewServer(port, logger)
	server.Start()
	t.Cleanup(func() { server.Shutdown() })

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 3*time.Second, 100*time.Millisecond)

	// Act
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
	assert.Contains(t, string(body), "# HELP", "response should contain Prometheus metrics")
}

func TestServer_HealthzEndpoint(t *testing.T) {
	// Arrange
	port := getFreePort(t)
	logger := zap.NewNop()
	server := metrics.NewServer(port, logger)
	server.Start()
	t.Cleanup(func() { server.Shutdown() })

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 3*time.Second, 100*time.Millisecond)

	// Act
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", string(body))
}

func TestServer_ShutdownIdempotent(t *testing.T) {
	// Arrange
	port := getFreePort(t)
	logger := zap.NewNop()
	server := metrics.NewServer(port, logger)
	server.Start()

	// Wait for server to be ready
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 3*time.Second, 100*time.Millisecond)

	// Act & Assert - calling shutdown multiple times should not panic
	assert.NotPanics(t, func() {
		server.Shutdown()
	})
	assert.NotPanics(t, func() {
		server.Shutdown()
	})
	assert.NotPanics(t, func() {
		server.Shutdown()
	})
}
