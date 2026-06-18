//go:build performance

package performance

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
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

func TestPerformance_ConcurrentRequests_Both(t *testing.T) {
	t.Parallel()

	ca, err := newBenchCA()
	require.NoError(t, err)

	address, cleanup := bothServer(&testing.B{}, ca)
	defer cleanup()

	clientCert, err := ca.issueCert("both-load-client", nil, nil)
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
	t.Logf("Both (mTLS+OIDC): %d requests in %v (%.0f req/s), success=%d, errors=%d",
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

// ---------------------------------------------------------------------------
// Live-server load tests (run against the running docker-compose server)
//
// These read connection/auth config from the environment (GRPC_ADDRESS,
// CERT_DIR, KEYCLOAK_URL, KC_REALM, KC_CLIENT_ID, KC_CLIENT_SECRET, AUTH_MODE)
// consistent with the e2e suite, and gracefully skip when prerequisites are
// unavailable. They report throughput and latency p50/p95/p99 per scenario.
// ---------------------------------------------------------------------------

// percentile returns the p-th percentile (0..100) of the sorted durations.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	rank := int(p/100*float64(len(sorted)-1) + 0.5)
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// loadResult captures the outcome of a live load run.
type loadResult struct {
	total      int64
	success    int64
	errors     int64
	elapsed    time.Duration
	latencies  []time.Duration
	firstError error
}

// runLiveLoad drives numWorkers x numRequests unary calls against the live
// server using a shared connection, refreshing the bearer token per worker when
// OIDC is enforced. It records per-request latency for percentile reporting.
func runLiveLoad(t *testing.T, client apiv1.TestServiceClient, numWorkers, numRequests int) *loadResult {
	t.Helper()

	var (
		successCount atomic.Int64
		errorCount   atomic.Int64
		wg           sync.WaitGroup
		mu           sync.Mutex
		firstErr     error
	)

	allLatencies := make([][]time.Duration, numWorkers)

	start := time.Now()
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Acquire a token once per worker (when required); reuse across the
			// worker's requests to model realistic token caching.
			baseCtx, err := liveAuthContext(t, context.Background())
			if err != nil {
				errorCount.Add(int64(numRequests))
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("token acquisition: %w", err)
				}
				mu.Unlock()
				return
			}

			lats := make([]time.Duration, 0, numRequests)
			for i := 0; i < numRequests; i++ {
				ctx, cancel := context.WithTimeout(baseCtx, 10*time.Second)
				msg := fmt.Sprintf("worker-%d-req-%d", workerID, i)

				reqStart := time.Now()
				resp, callErr := client.Unary(ctx, &apiv1.UnaryRequest{Message: msg})
				lat := time.Since(reqStart)
				cancel()

				if callErr != nil {
					errorCount.Add(1)
					mu.Lock()
					if firstErr == nil {
						firstErr = callErr
					}
					mu.Unlock()
					continue
				}
				lats = append(lats, lat)
				if resp.GetMessage() == msg {
					successCount.Add(1)
				}
			}
			allLatencies[workerID] = lats
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	merged := make([]time.Duration, 0, numWorkers*numRequests)
	for _, l := range allLatencies {
		merged = append(merged, l...)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i] < merged[j] })

	return &loadResult{
		total:      int64(numWorkers * numRequests),
		success:    successCount.Load(),
		errors:     errorCount.Load(),
		elapsed:    elapsed,
		latencies:  merged,
		firstError: firstErr,
	}
}

// logLoadResult prints a throughput + latency-percentile summary.
func logLoadResult(t *testing.T, scenario string, r *loadResult) {
	t.Helper()
	t.Logf("[%s] mode=%s %d requests in %v (%.0f req/s) success=%d errors=%d",
		scenario, liveCfg.AuthMode, r.total, r.elapsed,
		float64(r.total)/r.elapsed.Seconds(), r.success, r.errors,
	)
	if len(r.latencies) > 0 {
		t.Logf("[%s] latency p50=%v p95=%v p99=%v min=%v max=%v",
			scenario,
			percentile(r.latencies, 50),
			percentile(r.latencies, 95),
			percentile(r.latencies, 99),
			r.latencies[0],
			r.latencies[len(r.latencies)-1],
		)
	}
	if r.firstError != nil {
		t.Logf("[%s] first error: %v", scenario, r.firstError)
	}
}

// TestPerformance_LiveServer_ConcurrentRequests drives a concurrent unary load
// against the running server using the configured AUTH_MODE credentials and
// reports throughput + latency percentiles.
func TestPerformance_LiveServer_ConcurrentRequests(t *testing.T) {
	skipUnlessLivePrereqs(t)

	conn, client, err := liveClient(t)
	require.NoError(t, err)
	defer conn.Close()

	// Warm up the connection (TLS handshake, token fetch path).
	warmCtx, err := liveAuthContext(t, context.Background())
	require.NoError(t, err)
	wctx, wcancel := context.WithTimeout(warmCtx, 10*time.Second)
	_, err = client.Unary(wctx, &apiv1.UnaryRequest{Message: "warmup"})
	wcancel()
	require.NoError(t, err, "live warmup request must succeed")

	const (
		numWorkers  = 10
		numRequests = 100
	)

	res := runLiveLoad(t, client, numWorkers, numRequests)
	logLoadResult(t, "LiveServer_ConcurrentRequests", res)

	assert.Equal(t, res.total, res.success+res.errors)
	assert.Equal(t, int64(0), res.errors, "no errors expected against live server")
}

// TestPerformance_LiveServer_Sustained drives a higher-volume sustained load to
// surface tail latency under pressure.
func TestPerformance_LiveServer_Sustained(t *testing.T) {
	skipUnlessLivePrereqs(t)

	conn, client, err := liveClient(t)
	require.NoError(t, err)
	defer conn.Close()

	warmCtx, err := liveAuthContext(t, context.Background())
	require.NoError(t, err)
	wctx, wcancel := context.WithTimeout(warmCtx, 10*time.Second)
	_, err = client.Unary(wctx, &apiv1.UnaryRequest{Message: "warmup"})
	wcancel()
	require.NoError(t, err)

	const (
		numWorkers  = 20
		numRequests = 250
	)

	res := runLiveLoad(t, client, numWorkers, numRequests)
	logLoadResult(t, "LiveServer_Sustained", res)

	assert.Equal(t, res.total, res.success+res.errors)
	assert.Equal(t, int64(0), res.errors, "no errors expected under sustained load")
}

// TestPerformance_LiveServer_MetricsConsistency drives concurrent load against
// the live server while scraping the Prometheus /metrics endpoint, and verifies
// the started/handled counters increase by at least the request count and the
// in-flight gauge returns to baseline.
func TestPerformance_LiveServer_MetricsConsistency(t *testing.T) {
	skipUnlessLivePrereqs(t)

	metricsURL := getEnvOrDefault("METRICS_URL", "http://127.0.0.1:9090/metrics")
	if !metricsEndpointReachable(t, metricsURL) {
		t.Skipf("skipping: metrics endpoint %s not reachable", metricsURL)
	}

	conn, client, err := liveClient(t)
	require.NoError(t, err)
	defer conn.Close()

	const (
		numWorkers  = 10
		numRequests = 100
		service     = "api.v1.TestService"
	)

	startedLabels := map[string]string{
		"grpc_type": "unary", "grpc_service": service, "grpc_method": "Unary",
	}
	handledLabels := map[string]string{
		"grpc_type": "unary", "grpc_service": service, "grpc_method": "Unary", "grpc_code": "OK",
	}

	before := scrapeMetrics(t, metricsURL)
	startedBefore := metricCounter(before, "grpc_server_started_total", startedLabels)
	handledBefore := metricCounter(before, "grpc_server_handled_total", handledLabels)

	res := runLiveLoad(t, client, numWorkers, numRequests)
	logLoadResult(t, "LiveServer_MetricsConsistency", res)
	require.Equal(t, int64(0), res.errors, "no errors expected")

	// Counters update synchronously in the unary interceptor; a short settle is
	// nonetheless allowed for the in-flight gauge's deferred Dec().
	require.Eventually(t, func() bool {
		after := scrapeMetrics(t, metricsURL)
		startedDelta := metricCounter(after, "grpc_server_started_total", startedLabels) - startedBefore
		handledDelta := metricCounter(after, "grpc_server_handled_total", handledLabels) - handledBefore
		inFlight := metricGaugeSum(after, "grpc_server_in_flight_requests")
		return startedDelta >= float64(res.success) &&
			handledDelta >= float64(res.success) &&
			inFlight <= 0.0001
	}, 5*time.Second, 100*time.Millisecond,
		"started/handled counters should reconcile and in-flight gauge return to 0")
}

// ---------------------------------------------------------------------------
// Prometheus text-exposition scraping helpers (live /metrics endpoint)
// ---------------------------------------------------------------------------

// metricEndpointReachable reports whether the metrics endpoint responds 200.
func metricsEndpointReachable(t *testing.T, url string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// scrapeMetrics fetches the Prometheus text exposition body.
func scrapeMetrics(t *testing.T, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

// metricCounter parses the Prometheus text body and returns the value of the
// sample for `name` whose label set exactly matches `labels`. Returns 0 if not
// found.
func metricCounter(body, name string, labels map[string]string) float64 {
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, name+"{") && line != name && !strings.HasPrefix(line, name+" ") {
			continue
		}
		mName, mLabels, val, ok := parseSample(line)
		if !ok || mName != name {
			continue
		}
		if labelsEqual(mLabels, labels) {
			return val
		}
	}
	return 0
}

// metricGaugeSum sums all sample values across the metric family `name`.
func metricGaugeSum(body, name string) float64 {
	var sum float64
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		mName, _, val, ok := parseSample(line)
		if ok && mName == name {
			sum += val
		}
	}
	return sum
}

// parseSample parses one Prometheus exposition line into name, labels, value.
func parseSample(line string) (name string, labels map[string]string, value float64, ok bool) {
	labels = map[string]string{}
	brace := strings.IndexByte(line, '{')
	if brace == -1 {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", nil, 0, false
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return "", nil, 0, false
		}
		return fields[0], labels, v, true
	}
	name = line[:brace]
	close := strings.IndexByte(line, '}')
	if close == -1 || close < brace {
		return "", nil, 0, false
	}
	labelStr := line[brace+1 : close]
	for _, kv := range splitLabels(labelStr) {
		eq := strings.IndexByte(kv, '=')
		if eq == -1 {
			continue
		}
		k := strings.TrimSpace(kv[:eq])
		v := strings.Trim(strings.TrimSpace(kv[eq+1:]), `"`)
		labels[k] = v
	}
	rest := strings.TrimSpace(line[close+1:])
	fields := strings.Fields(rest)
	if len(fields) < 1 {
		return "", nil, 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "", nil, 0, false
	}
	return name, labels, v, true
}

// splitLabels splits a label string on commas that are not inside quotes.
func splitLabels(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch r {
		case '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case ',':
			if inQuote {
				cur.WriteRune(r)
			} else {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// labelsEqual reports whether got contains exactly the want label set.
func labelsEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}
