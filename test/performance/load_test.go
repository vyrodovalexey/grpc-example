//go:build performance

package performance

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

func TestPerformance_ConcurrentRequests_Insecure(t *testing.T) {
	t.Parallel()

	address, cleanup := insecureServer(&testing.B{})
	defer cleanup()

	conn, client := insecureClient(&testing.B{}, address)
	defer conn.Close()

	const (
		numWorkers  = 10
		numRequests = 100
	)

	var (
		successCount atomic.Int64
		errorCount   atomic.Int64
		wg           sync.WaitGroup
	)

	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for i := 0; i < numRequests; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				msg := fmt.Sprintf("worker-%d-req-%d", workerID, i)

				resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: msg})
				cancel()

				if err != nil {
					errorCount.Add(1)
					continue
				}
				if resp.GetMessage() == msg {
					successCount.Add(1)
				}
			}
		}(w)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalRequests := int64(numWorkers * numRequests)
	t.Logf("Insecure: %d requests in %v (%.0f req/s), success=%d, errors=%d",
		totalRequests, elapsed,
		float64(totalRequests)/elapsed.Seconds(),
		successCount.Load(), errorCount.Load(),
	)

	assert.Equal(t, totalRequests, successCount.Load()+errorCount.Load())
	assert.Equal(t, int64(0), errorCount.Load(), "no errors expected")
}

func TestPerformance_ConcurrentRequests_MTLS(t *testing.T) {
	t.Parallel()

	ca, err := newBenchCA()
	require.NoError(t, err)

	address, cleanup := mtlsServer(&testing.B{}, ca)
	defer cleanup()

	clientCert, err := ca.issueCert("load-client", nil, nil)
	require.NoError(t, err)

	conn, client := mtlsClient(&testing.B{}, address, clientCert, ca.pool)
	defer conn.Close()

	const (
		numWorkers  = 10
		numRequests = 100
	)

	var (
		successCount atomic.Int64
		errorCount   atomic.Int64
		wg           sync.WaitGroup
	)

	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for i := 0; i < numRequests; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				msg := fmt.Sprintf("worker-%d-req-%d", workerID, i)

				resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: msg})
				cancel()

				if err != nil {
					errorCount.Add(1)
					continue
				}
				if resp.GetMessage() == msg {
					successCount.Add(1)
				}
			}
		}(w)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalRequests := int64(numWorkers * numRequests)
	t.Logf("mTLS: %d requests in %v (%.0f req/s), success=%d, errors=%d",
		totalRequests, elapsed,
		float64(totalRequests)/elapsed.Seconds(),
		successCount.Load(), errorCount.Load(),
	)

	assert.Equal(t, totalRequests, successCount.Load()+errorCount.Load())
	assert.Equal(t, int64(0), errorCount.Load(), "no errors expected")
}

func TestPerformance_ConcurrentRequests_OIDC(t *testing.T) {
	t.Parallel()

	address, cleanup := oidcServer(&testing.B{})
	defer cleanup()

	conn, client := insecureClient(&testing.B{}, address)
	defer conn.Close()

	const (
		numWorkers  = 10
		numRequests = 100
	)

	var (
		successCount atomic.Int64
		errorCount   atomic.Int64
		wg           sync.WaitGroup
	)

	start := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for i := 0; i < numRequests; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				ctx = contextWithBearerToken(ctx, "load-test-token")
				msg := fmt.Sprintf("worker-%d-req-%d", workerID, i)

				resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: msg})
				cancel()

				if err != nil {
					errorCount.Add(1)
					continue
				}
				if resp.GetMessage() == msg {
					successCount.Add(1)
				}
			}
		}(w)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalRequests := int64(numWorkers * numRequests)
	t.Logf("OIDC: %d requests in %v (%.0f req/s), success=%d, errors=%d",
		totalRequests, elapsed,
		float64(totalRequests)/elapsed.Seconds(),
		successCount.Load(), errorCount.Load(),
	)

	assert.Equal(t, totalRequests, successCount.Load()+errorCount.Load())
	assert.Equal(t, int64(0), errorCount.Load(), "no errors expected")
}

func TestPerformance_ConnectionPooling_MTLS(t *testing.T) {
	t.Parallel()

	ca, err := newBenchCA()
	require.NoError(t, err)

	address, cleanup := mtlsServer(&testing.B{}, ca)
	defer cleanup()

	clientCert, err := ca.issueCert("pool-client", nil, nil)
	require.NoError(t, err)

	// Test with a single shared connection (connection pooling).
	conn, client := mtlsClient(&testing.B{}, address, clientCert, ca.pool)
	defer conn.Close()

	const numRequests = 50

	start := time.Now()
	for i := 0; i < numRequests; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "pooled"})
		cancel()
		require.NoError(t, err)
	}
	pooledElapsed := time.Since(start)

	t.Logf("Connection pooling (shared conn): %d requests in %v (%.0f req/s)",
		numRequests, pooledElapsed,
		float64(numRequests)/pooledElapsed.Seconds(),
	)

	// Test with new connections per request (no pooling).
	start = time.Now()
	for i := 0; i < numRequests; i++ {
		newConn, newClient := mtlsClient(&testing.B{}, address, clientCert, ca.pool)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := newClient.Unary(ctx, &apiv1.UnaryRequest{Message: "not-pooled"})
		cancel()
		newConn.Close()
		require.NoError(t, err)
	}
	unpooledElapsed := time.Since(start)

	t.Logf("No connection pooling (new conn): %d requests in %v (%.0f req/s)",
		numRequests, unpooledElapsed,
		float64(numRequests)/unpooledElapsed.Seconds(),
	)

	// Connection pooling should be faster.
	t.Logf("Pooling speedup: %.2fx", float64(unpooledElapsed)/float64(pooledElapsed))
}

func TestPerformance_TokenCachingEffectiveness(t *testing.T) {
	t.Parallel()

	address, cleanup := oidcServer(&testing.B{})
	defer cleanup()

	conn, client := insecureClient(&testing.B{}, address)
	defer conn.Close()

	const numRequests = 100

	// Test with the same token (simulating caching).
	cachedCtx := contextWithBearerToken(context.Background(), "cached-token")

	start := time.Now()
	for i := 0; i < numRequests; i++ {
		ctx, cancel := context.WithTimeout(cachedCtx, 10*time.Second)
		_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "cached"})
		cancel()
		require.NoError(t, err)
	}
	cachedElapsed := time.Since(start)

	t.Logf("Same token (cached): %d requests in %v (%.0f req/s)",
		numRequests, cachedElapsed,
		float64(numRequests)/cachedElapsed.Seconds(),
	)

	// Test with different tokens per request (no caching benefit).
	start = time.Now()
	for i := 0; i < numRequests; i++ {
		ctx := contextWithBearerToken(context.Background(), fmt.Sprintf("token-%d", i))
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "uncached"})
		cancel()
		require.NoError(t, err)
	}
	uncachedElapsed := time.Since(start)

	t.Logf("Different tokens (uncached): %d requests in %v (%.0f req/s)",
		numRequests, uncachedElapsed,
		float64(numRequests)/uncachedElapsed.Seconds(),
	)
}
