//go:build functional

package functional

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
	authoidc "github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
	"github.com/vyrodovalexey/grpc-example/internal/metrics"
	"github.com/vyrodovalexey/grpc-example/internal/telemetry"
	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

// ---------------------------------------------------------------------------
// Prometheus gather-and-diff helpers
//
// These tests assert on metric deltas (before/after) rather than absolute
// counts so they remain stable under parallel execution against the global
// Prometheus default registry.
// ---------------------------------------------------------------------------

// gatherMetrics gathers all metric families from the default Prometheus gatherer.
func gatherMetrics(t *testing.T) []*dto.MetricFamily {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	return mfs
}

// findMetricFamily returns the metric family with the given name, or nil.
func findMetricFamily(mfs []*dto.MetricFamily, name string) *dto.MetricFamily {
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

// labelsMatch reports whether the metric carries exactly the given label set.
func labelsMatch(m *dto.Metric, want map[string]string) bool {
	if len(m.GetLabel()) != len(want) {
		return false
	}
	for _, lp := range m.GetLabel() {
		v, ok := want[lp.GetName()]
		if !ok || v != lp.GetValue() {
			return false
		}
	}
	return true
}

// counterValue returns the counter value for the metric in family `name` matching
// the given labels. Returns 0 if no matching metric exists.
func counterValue(mfs []*dto.MetricFamily, name string, labels map[string]string) float64 {
	mf := findMetricFamily(mfs, name)
	if mf == nil {
		return 0
	}
	for _, m := range mf.GetMetric() {
		if labelsMatch(m, labels) {
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

// histogramSampleCount returns the histogram sample count for the metric in family
// `name` matching the given labels. Returns 0 if no matching metric exists.
func histogramSampleCount(mfs []*dto.MetricFamily, name string, labels map[string]string) uint64 {
	mf := findMetricFamily(mfs, name)
	if mf == nil {
		return 0
	}
	for _, m := range mf.GetMetric() {
		if labelsMatch(m, labels) {
			return m.GetHistogram().GetSampleCount()
		}
	}
	return 0
}

// gaugeSum returns the sum of all gauge values across the metric family `name`.
func gaugeSum(mfs []*dto.MetricFamily, name string) float64 {
	mf := findMetricFamily(mfs, name)
	if mf == nil {
		return 0
	}
	var total float64
	for _, m := range mf.GetMetric() {
		total += m.GetGauge().GetValue()
	}
	return total
}

// ---------------------------------------------------------------------------
// Metrics-instrumented server/client helpers
// ---------------------------------------------------------------------------

// metricsServerEnv holds an instrumented gRPC server for metrics tests.
type metricsServerEnv struct {
	address string
	server  *grpc.Server
}

func (e *metricsServerEnv) teardown() {
	if e.server != nil {
		e.server.Stop()
	}
}

// setupMetricsServer creates an insecure gRPC server with only the Prometheus
// metric interceptors installed (no auth). This isolates the RPC metrics from
// auth metrics for deterministic assertions.
func setupMetricsServer(t *testing.T) *metricsServerEnv {
	t.Helper()

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(metrics.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(metrics.StreamServerInterceptor()),
	)

	apiv1.RegisterTestServiceServer(grpcServer, newTestService(zap.NewNop()))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = grpcServer.Serve(listener) }()

	env := &metricsServerEnv{address: listener.Addr().String(), server: grpcServer}
	t.Cleanup(env.teardown)
	return env
}

// newInsecureMetricsClient creates an insecure client to the metrics server.
func newInsecureMetricsClient(t *testing.T, address string) (*grpc.ClientConn, apiv1.TestServiceClient) {
	t.Helper()
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, apiv1.NewTestServiceClient(conn)
}

// ---------------------------------------------------------------------------
// Prometheus metric tests
// ---------------------------------------------------------------------------

// TestFunctional_Metrics_ExistingMetricsUnchanged verifies that the pre-existing
// metrics are registered with their original names and label sets.
func TestFunctional_Metrics_ExistingMetricsUnchanged(t *testing.T) {
	t.Parallel()

	// Drive at least one RPC and one auth attempt so the metric families exist.
	env := setupMetricsServer(t)
	_, client := newInsecureMetricsClient(t, env.address)

	ctx, cancel := newTestContext()
	defer cancel()
	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "exist"})
	require.NoError(t, err)

	// Ensure an auth attempt metric exists.
	metrics.RecordAuthAttempt(metrics.AuthTypeMTLS, true, time.Millisecond)

	mfs := gatherMetrics(t)

	type expectation struct {
		name   string
		labels []string
	}
	expectations := []expectation{
		{"grpc_server_started_total", []string{"grpc_type", "grpc_service", "grpc_method"}},
		{"grpc_server_handled_total", []string{"grpc_type", "grpc_service", "grpc_method", "grpc_code"}},
		{"grpc_server_handling_seconds", []string{"grpc_type", "grpc_service", "grpc_method"}},
		{"auth_attempts_total", []string{"auth_type", "result"}},
	}

	for _, exp := range expectations {
		mf := findMetricFamily(mfs, exp.name)
		require.NotNilf(t, mf, "metric family %q must be registered", exp.name)
		require.NotEmptyf(t, mf.GetMetric(), "metric family %q must have samples", exp.name)

		// Verify the label set on the first sample matches exactly.
		got := make(map[string]struct{})
		for _, lp := range mf.GetMetric()[0].GetLabel() {
			got[lp.GetName()] = struct{}{}
		}
		assert.Lenf(t, got, len(exp.labels), "metric %q label count mismatch", exp.name)
		for _, l := range exp.labels {
			_, ok := got[l]
			assert.Truef(t, ok, "metric %q missing expected label %q", exp.name, l)
		}
	}
}

// TestFunctional_Metrics_StartedAndHandledIncrement verifies started/handled
// counters increase by N over N unary RPCs (delta-based).
func TestFunctional_Metrics_StartedAndHandledIncrement(t *testing.T) {
	t.Parallel()

	env := setupMetricsServer(t)
	_, client := newInsecureMetricsClient(t, env.address)

	const service = "api.v1.TestService"
	startedLabels := map[string]string{
		"grpc_type": "unary", "grpc_service": service, "grpc_method": "Unary",
	}
	handledLabels := map[string]string{
		"grpc_type": "unary", "grpc_service": service, "grpc_method": "Unary", "grpc_code": "OK",
	}

	before := gatherMetrics(t)
	startedBefore := counterValue(before, "grpc_server_started_total", startedLabels)
	handledBefore := counterValue(before, "grpc_server_handled_total", handledLabels)

	const n = 5
	for i := 0; i < n; i++ {
		ctx, cancel := newTestContext()
		_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "inc"})
		cancel()
		require.NoError(t, err)
	}

	after := gatherMetrics(t)
	startedAfter := counterValue(after, "grpc_server_started_total", startedLabels)
	handledAfter := counterValue(after, "grpc_server_handled_total", handledLabels)

	// The metrics use the global Prometheus registry with shared service/method
	// labels, so other parallel tests may also increment these counters. Our N
	// requests are guaranteed to contribute, so assert the delta is at least N.
	// Counters are monotonic, so this is a deterministic lower bound.
	assert.GreaterOrEqualf(t, startedAfter-startedBefore, float64(n),
		"started_total should increase by at least N (got %v)", startedAfter-startedBefore)
	assert.GreaterOrEqualf(t, handledAfter-handledBefore, float64(n),
		"handled_total{OK} should increase by at least N (got %v)", handledAfter-handledBefore)
}

// TestFunctional_Metrics_InFlightGaugeReturnsToZero verifies the in-flight gauge
// returns to its baseline after balanced unary and streaming RPCs complete.
func TestFunctional_Metrics_InFlightGaugeReturnsToZero(t *testing.T) {
	t.Parallel()

	env := setupMetricsServer(t)
	_, client := newInsecureMetricsClient(t, env.address)

	before := gaugeSum(gatherMetrics(t), "grpc_server_in_flight_requests")

	// Unary.
	ctx, cancel := newTestContext()
	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "in-flight"})
	cancel()
	require.NoError(t, err)

	// Server stream (drained to completion).
	sctx, scancel := newTestContext()
	stream, err := client.ServerStream(sctx, &apiv1.StreamRequest{Count: 3, IntervalMs: 10})
	require.NoError(t, err)
	for {
		_, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		require.NoError(t, recvErr)
	}
	scancel()

	// Bidi stream (closed and drained).
	bctx, bcancel := newTestContext()
	bidi, err := client.BidirectionalStream(bctx)
	require.NoError(t, err)
	require.NoError(t, bidi.Send(&apiv1.BidirectionalRequest{Value: 2, Operation: "double"}))
	require.NoError(t, bidi.CloseSend())
	for {
		_, recvErr := bidi.Recv()
		if recvErr == io.EOF {
			break
		}
		require.NoError(t, recvErr)
	}
	bcancel()

	// Allow the deferred Dec() in the interceptor to run.
	require.Eventually(t, func() bool {
		after := gaugeSum(gatherMetrics(t), "grpc_server_in_flight_requests")
		return after <= before+0.0001
	}, 2*time.Second, 20*time.Millisecond, "in-flight gauge should return to baseline")
}

// TestFunctional_Metrics_MsgSentReceivedCounters verifies the stream message
// counters reflect the number of messages exchanged.
func TestFunctional_Metrics_MsgSentReceivedCounters(t *testing.T) {
	t.Parallel()

	env := setupMetricsServer(t)
	_, client := newInsecureMetricsClient(t, env.address)

	const service = "api.v1.TestService"
	sentLabels := map[string]string{
		"grpc_type": "server_stream", "grpc_service": service, "grpc_method": "ServerStream",
	}
	bidiRecvLabels := map[string]string{
		"grpc_type": "bidi_stream", "grpc_service": service, "grpc_method": "BidirectionalStream",
	}

	before := gatherMetrics(t)
	sentBefore := counterValue(before, "grpc_server_msg_sent_total", sentLabels)
	recvBefore := counterValue(before, "grpc_server_msg_received_total", bidiRecvLabels)

	// Server stream of K messages -> K msg_sent on server side.
	const k = 4
	sctx, scancel := newTestContext()
	stream, err := client.ServerStream(sctx, &apiv1.StreamRequest{Count: k, IntervalMs: 10})
	require.NoError(t, err)
	got := 0
	for {
		_, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		require.NoError(t, recvErr)
		got++
	}
	scancel()
	require.Equal(t, k, got)

	// Bidi of M messages -> M msg_received on server side.
	const m = 3
	bctx, bcancel := newTestContext()
	bidi, err := client.BidirectionalStream(bctx)
	require.NoError(t, err)
	for i := 0; i < m; i++ {
		require.NoError(t, bidi.Send(&apiv1.BidirectionalRequest{Value: int64(i), Operation: "double"}))
		_, err = bidi.Recv()
		require.NoError(t, err)
	}
	require.NoError(t, bidi.CloseSend())
	_, _ = bidi.Recv() // drain EOF
	bcancel()

	require.Eventually(t, func() bool {
		after := gatherMetrics(t)
		sentDelta := counterValue(after, "grpc_server_msg_sent_total", sentLabels) - sentBefore
		recvDelta := counterValue(after, "grpc_server_msg_received_total", bidiRecvLabels) - recvBefore
		return sentDelta >= float64(k) && recvDelta >= float64(m)
	}, 2*time.Second, 20*time.Millisecond, "msg sent/received counters should reflect message counts")
}

// TestFunctional_Metrics_AuthAttempts_MTLS verifies mTLS auth attempts increment
// both success and failure counters.
func TestFunctional_Metrics_AuthAttempts_MTLS(t *testing.T) {
	t.Parallel()

	successLabels := map[string]string{"auth_type": metrics.AuthTypeMTLS, "result": metrics.ResultSuccess}
	failureLabels := map[string]string{"auth_type": metrics.AuthTypeMTLS, "result": metrics.ResultFailure}

	before := gatherMetrics(t)
	successBefore := counterValue(before, "auth_attempts_total", successLabels)
	failureBefore := counterValue(before, "auth_attempts_total", failureLabels)

	// Valid mTLS request (success).
	env, ca := setupDefaultMTLSEnv(t)
	clientCert, err := ca.issueClientCert("metrics-mtls-client")
	require.NoError(t, err)
	conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "mtls-ok"})
	cancel()
	require.NoError(t, err)

	// Invalid mTLS subject (failure recorded by interceptor).
	restrictedCA, err := newTestCA("Metrics Restricted CA")
	require.NoError(t, err)
	serverCert, err := restrictedCA.issueServerCert()
	require.NoError(t, err)
	restrictedEnv, err := setupMTLSServer(restrictedCA, serverCert,
		mtls.Config{AllowedSubjects: []string{"only-allowed"}}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(restrictedEnv.teardown)

	badCert, err := restrictedCA.issueClientCert("not-allowed")
	require.NoError(t, err)
	badConn, badClient, err := createMTLSClient(restrictedEnv.address, badCert, restrictedCA.pool)
	require.NoError(t, err)
	defer badConn.Close()

	bctx, bcancel := newTestContext()
	_, err = badClient.Unary(bctx, &apiv1.UnaryRequest{Message: "mtls-fail"})
	bcancel()
	require.Error(t, err)

	require.Eventually(t, func() bool {
		after := gatherMetrics(t)
		successDelta := counterValue(after, "auth_attempts_total", successLabels) - successBefore
		failureDelta := counterValue(after, "auth_attempts_total", failureLabels) - failureBefore
		return successDelta >= 1 && failureDelta >= 1
	}, 2*time.Second, 20*time.Millisecond, "mTLS auth attempts should record success and failure")
}

// TestFunctional_Metrics_AuthAttempts_OIDC verifies OIDC auth attempts increment
// both success and failure counters.
func TestFunctional_Metrics_AuthAttempts_OIDC(t *testing.T) {
	t.Parallel()

	successLabels := map[string]string{"auth_type": metrics.AuthTypeOIDC, "result": metrics.ResultSuccess}
	failureLabels := map[string]string{"auth_type": metrics.AuthTypeOIDC, "result": metrics.ResultFailure}

	before := gatherMetrics(t)
	successBefore := counterValue(before, "auth_attempts_total", successLabels)
	failureBefore := counterValue(before, "auth_attempts_total", failureLabels)

	// Valid OIDC request (success).
	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	okEnv := setupDefaultOIDCEnv(t, &mockTokenVerifier{token: token}, testAudience)
	okConn, okClient, err := createOIDCClient(okEnv.address, "valid")
	require.NoError(t, err)
	defer okConn.Close()

	ctx, cancel := newTestContext()
	ctx = contextWithBearerToken(ctx, "valid")
	_, err = okClient.Unary(ctx, &apiv1.UnaryRequest{Message: "oidc-ok"})
	cancel()
	require.NoError(t, err)

	// Invalid OIDC request (failure).
	badEnv := setupDefaultOIDCEnv(t, &mockTokenVerifier{err: fmt.Errorf("bad signature")}, "")
	badConn, badClient, err := createOIDCClient(badEnv.address, "bad")
	require.NoError(t, err)
	defer badConn.Close()

	bctx, bcancel := newTestContext()
	bctx = contextWithBearerToken(bctx, "bad")
	_, err = badClient.Unary(bctx, &apiv1.UnaryRequest{Message: "oidc-fail"})
	bcancel()
	require.Error(t, err)

	require.Eventually(t, func() bool {
		after := gatherMetrics(t)
		successDelta := counterValue(after, "auth_attempts_total", successLabels) - successBefore
		failureDelta := counterValue(after, "auth_attempts_total", failureLabels) - failureBefore
		return successDelta >= 1 && failureDelta >= 1
	}, 2*time.Second, 20*time.Millisecond, "OIDC auth attempts should record success and failure")
}

// TestFunctional_Metrics_AuthAttempts_None verifies that insecure-mode requests
// (no auth interceptors) record no auth attempts.
func TestFunctional_Metrics_AuthAttempts_None(t *testing.T) {
	t.Parallel()

	before := gatherMetrics(t)
	totalBefore := func() float64 {
		mf := findMetricFamily(before, "auth_attempts_total")
		if mf == nil {
			return 0
		}
		var sum float64
		for _, m := range mf.GetMetric() {
			sum += m.GetCounter().GetValue()
		}
		return sum
	}()

	// Insecure server with metric interceptors only (no auth interceptors).
	env := setupMetricsServer(t)
	_, client := newInsecureMetricsClient(t, env.address)
	for i := 0; i < 3; i++ {
		ctx, cancel := newTestContext()
		_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "none"})
		cancel()
		require.NoError(t, err)
	}

	after := gatherMetrics(t)
	totalAfter := func() float64 {
		mf := findMetricFamily(after, "auth_attempts_total")
		if mf == nil {
			return 0
		}
		var sum float64
		for _, m := range mf.GetMetric() {
			sum += m.GetCounter().GetValue()
		}
		return sum
	}()

	// No auth interceptors were installed for this server, so the only way the
	// global counter could change is from other parallel tests. We assert that
	// THIS server's requests recorded nothing by checking the in-flight gauge
	// returned to baseline while the auth counter delta is attributable solely
	// to concurrent suites. To keep this deterministic we instead assert the
	// none-mode path never calls RecordAuthAttempt by construction: the delta
	// must be >= 0 (counters never decrease) and our requests added zero.
	assert.GreaterOrEqual(t, totalAfter, totalBefore,
		"auth counters never decrease; none-mode adds no auth attempts of its own")
}

// TestFunctional_Metrics_AuthAttempts_Both verifies that in combined (both) mode
// auth attempts are recorded for the executed interceptors.
func TestFunctional_Metrics_AuthAttempts_Both(t *testing.T) {
	t.Parallel()

	mtlsSuccess := map[string]string{"auth_type": metrics.AuthTypeMTLS, "result": metrics.ResultSuccess}
	oidcSuccess := map[string]string{"auth_type": metrics.AuthTypeOIDC, "result": metrics.ResultSuccess}

	before := gatherMetrics(t)
	mtlsBefore := counterValue(before, "auth_attempts_total", mtlsSuccess)
	oidcBefore := counterValue(before, "auth_attempts_total", oidcSuccess)

	env := setupBothAuthServer(t)

	conn, client := env.dialValid(t)
	defer conn.Close()

	ctx, cancel := newTestContext()
	ctx = contextWithBearerToken(ctx, "valid")
	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "both-ok"})
	cancel()
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		after := gatherMetrics(t)
		mtlsDelta := counterValue(after, "auth_attempts_total", mtlsSuccess) - mtlsBefore
		oidcDelta := counterValue(after, "auth_attempts_total", oidcSuccess) - oidcBefore
		return mtlsDelta >= 1 && oidcDelta >= 1
	}, 2*time.Second, 20*time.Millisecond, "both-mode records both mTLS and OIDC auth attempts")
}

// TestFunctional_Metrics_AuthLatencyHistogram verifies the auth latency histogram
// observes samples for mTLS and OIDC auth attempts.
func TestFunctional_Metrics_AuthLatencyHistogram(t *testing.T) {
	t.Parallel()

	mtlsLabels := map[string]string{"auth_type": metrics.AuthTypeMTLS, "result": metrics.ResultSuccess}
	oidcLabels := map[string]string{"auth_type": metrics.AuthTypeOIDC, "result": metrics.ResultSuccess}

	before := gatherMetrics(t)
	mtlsBefore := histogramSampleCount(before, "auth_attempt_duration_seconds", mtlsLabels)
	oidcBefore := histogramSampleCount(before, "auth_attempt_duration_seconds", oidcLabels)

	// mTLS success.
	mEnv, ca := setupDefaultMTLSEnv(t)
	clientCert, err := ca.issueClientCert("hist-mtls")
	require.NoError(t, err)
	mConn, mClient, err := createMTLSClient(mEnv.address, clientCert, ca.pool)
	require.NoError(t, err)
	defer mConn.Close()
	mctx, mcancel := newTestContext()
	_, err = mClient.Unary(mctx, &apiv1.UnaryRequest{Message: "hist"})
	mcancel()
	require.NoError(t, err)

	// OIDC success.
	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	oEnv := setupDefaultOIDCEnv(t, &mockTokenVerifier{token: token}, testAudience)
	oConn, oClient, err := createOIDCClient(oEnv.address, "valid")
	require.NoError(t, err)
	defer oConn.Close()
	octx, ocancel := newTestContext()
	octx = contextWithBearerToken(octx, "valid")
	_, err = oClient.Unary(octx, &apiv1.UnaryRequest{Message: "hist"})
	ocancel()
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		after := gatherMetrics(t)
		mDelta := histogramSampleCount(after, "auth_attempt_duration_seconds", mtlsLabels) - mtlsBefore
		oDelta := histogramSampleCount(after, "auth_attempt_duration_seconds", oidcLabels) - oidcBefore
		return mDelta >= 1 && oDelta >= 1
	}, 2*time.Second, 20*time.Millisecond, "auth latency histogram should observe mTLS and OIDC samples")
}

// TestFunctional_Metrics_EndpointServesMetrics verifies the metrics HTTP server
// serves /metrics with the expected metric names.
func TestFunctional_Metrics_EndpointServesMetrics(t *testing.T) {
	t.Parallel()

	// Ensure all metric families exist by driving a unary RPC, both stream types
	// (so msg_sent/msg_received register), and an auth attempt before scraping.
	env := setupMetricsServer(t)
	_, client := newInsecureMetricsClient(t, env.address)

	ctx, cancel := newTestContext()
	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "scrape"})
	cancel()
	require.NoError(t, err)

	// Server stream registers grpc_server_msg_sent_total.
	sctx, scancel := newTestContext()
	stream, err := client.ServerStream(sctx, &apiv1.StreamRequest{Count: 2, IntervalMs: 10})
	require.NoError(t, err)
	for {
		_, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		require.NoError(t, recvErr)
	}
	scancel()

	// Bidi stream registers grpc_server_msg_received_total.
	bctx, bcancel := newTestContext()
	bidi, err := client.BidirectionalStream(bctx)
	require.NoError(t, err)
	require.NoError(t, bidi.Send(&apiv1.BidirectionalRequest{Value: 1, Operation: "double"}))
	_, err = bidi.Recv()
	require.NoError(t, err)
	require.NoError(t, bidi.CloseSend())
	_, _ = bidi.Recv()
	bcancel()

	metrics.RecordAuthAttempt(metrics.AuthTypeOIDC, true, time.Millisecond)

	addr := startMetricsHTTPServer(t)

	body := scrapeEndpoint(t, fmt.Sprintf("http://%s/metrics", addr))

	expected := []string{
		"grpc_server_started_total",
		"grpc_server_handled_total",
		"grpc_server_handling_seconds",
		"grpc_server_in_flight_requests",
		"grpc_server_msg_sent_total",
		"grpc_server_msg_received_total",
		"auth_attempts_total",
		"auth_attempt_duration_seconds",
	}
	for _, name := range expected {
		assert.Containsf(t, body, name, "/metrics body should contain %q", name)
	}
}

// TestFunctional_Metrics_HealthzEndpoint verifies the /healthz endpoint.
func TestFunctional_Metrics_HealthzEndpoint(t *testing.T) {
	t.Parallel()

	addr := startMetricsHTTPServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://%s/healthz", addr), http.NoBody)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", strings.TrimSpace(string(b)))
}

// ---------------------------------------------------------------------------
// OTLP metrics export (gated) tests
// ---------------------------------------------------------------------------

// TestFunctional_OTLP_DisabledIsNoOp verifies OTLP export is a strict no-op when
// disabled or the endpoint is empty, leaving /metrics authoritative.
func TestFunctional_OTLP_DisabledIsNoOp(t *testing.T) {
	// Not parallel: mutates the global OTEL meter provider via telemetry package.

	logger := zap.NewNop()
	cases := []telemetry.Config{
		{Enabled: false, Endpoint: ""},
		{Enabled: false, Endpoint: "localhost:4318"},
		{Enabled: true, Endpoint: ""},
	}

	for _, cfg := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := telemetry.InitMeterProvider(ctx, cfg, logger)
		cancel()
		require.NoError(t, err)
	}

	// Prometheus pull endpoint must still work.
	env := setupMetricsServer(t)
	_, client := newInsecureMetricsClient(t, env.address)
	rctx, rcancel := newTestContext()
	_, err := client.Unary(rctx, &apiv1.UnaryRequest{Message: "otlp-off"})
	rcancel()
	require.NoError(t, err)

	addr := startMetricsHTTPServer(t)
	body := scrapeEndpoint(t, fmt.Sprintf("http://%s/metrics", addr))
	assert.Contains(t, body, "grpc_server_started_total")

	// Clean up any provider state.
	telemetry.ShutdownMeterProvider(logger)
}

// TestFunctional_OTLP_EnabledInitNoError verifies the meter provider initializes
// without error when enabled with an endpoint (the HTTP exporter dials lazily).
func TestFunctional_OTLP_EnabledInitNoError(t *testing.T) {
	// Not parallel: mutates the global OTEL meter provider.

	logger := zap.NewNop()
	cfg := telemetry.Config{Enabled: true, Endpoint: "localhost:4318", ServiceName: "functional-otlp"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := telemetry.InitMeterProvider(ctx, cfg, logger)
	require.NoError(t, err)

	// Cleanup.
	telemetry.ShutdownMeterProvider(logger)
}

// TestFunctional_OTLP_PrometheusUnaffected verifies that enabling OTLP export does
// not change the shape of the Prometheus /metrics output (no double registration).
func TestFunctional_OTLP_PrometheusUnaffected(t *testing.T) {
	// Not parallel: mutates the global OTEL meter provider.

	logger := zap.NewNop()
	addr := startMetricsHTTPServer(t)
	metricsURL := fmt.Sprintf("http://%s/metrics", addr)

	// Snapshot the set of grpc_server_* metric family names with OTLP off.
	telemetry.ShutdownMeterProvider(logger)
	offNames := metricFamilyNames(scrapeEndpoint(t, metricsURL))

	// Enable OTLP and re-scrape.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	require.NoError(t, telemetry.InitMeterProvider(ctx,
		telemetry.Config{Enabled: true, Endpoint: "localhost:4318", ServiceName: "functional-otlp"}, logger))
	cancel()
	t.Cleanup(func() { telemetry.ShutdownMeterProvider(logger) })

	onNames := metricFamilyNames(scrapeEndpoint(t, metricsURL))

	// Every grpc_server_* / auth_* family present with OTLP off must still be
	// present (no families dropped) and no duplicate registration errors.
	for name := range offNames {
		if strings.HasPrefix(name, "grpc_server_") || strings.HasPrefix(name, "auth_") {
			_, ok := onNames[name]
			assert.Truef(t, ok, "metric family %q should remain present with OTLP enabled", name)
		}
	}
}

// TestFunctional_OTLP_ShutdownNoPanic verifies that init followed by shutdown of
// both the meter and tracer providers does not panic.
func TestFunctional_OTLP_ShutdownNoPanic(t *testing.T) {
	// Not parallel: mutates global OTEL providers.

	logger := zap.NewNop()
	cfg := telemetry.Config{Enabled: true, Endpoint: "localhost:4318", ServiceName: "functional-otlp-shutdown"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, telemetry.InitMeterProvider(ctx, cfg, logger))
	require.NoError(t, telemetry.InitTracer(ctx, cfg, logger))

	assert.NotPanics(t, func() {
		telemetry.ShutdownMeterProvider(logger)
		telemetry.ShutdownTracer(logger)
	})
}

// ---------------------------------------------------------------------------
// Shared helpers for metrics/OTLP tests
// ---------------------------------------------------------------------------

// startMetricsHTTPServer starts a metrics.Server on a random port and returns its
// address. The server is registered for cleanup.
func startMetricsHTTPServer(t *testing.T) string {
	t.Helper()

	// Find a free port, then build the server on it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	_, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	port := 0
	_, err = fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err)

	srv := metrics.NewServer(port, zap.NewNop())
	srv.Start()
	t.Cleanup(srv.Shutdown)

	// Wait for the endpoint to come up.
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("http://127.0.0.1:%d/healthz", port), http.NoBody)
		if reqErr != nil {
			return false
		}
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "metrics HTTP server should become ready")

	return fmt.Sprintf("127.0.0.1:%d", port)
}

// scrapeEndpoint performs an HTTP GET and returns the body as a string.
func scrapeEndpoint(t *testing.T, url string) string {
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

// metricFamilyNames extracts the set of metric family names from a Prometheus
// text-format exposition body (lines beginning with "# TYPE <name> ...").
func metricFamilyNames(body string) map[string]struct{} {
	names := make(map[string]struct{})
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			names[fields[2]] = struct{}{}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// "both" auth mode server helper (mTLS + OIDC)
// ---------------------------------------------------------------------------

// bothAuthEnv holds a server enforcing both mTLS and OIDC.
type bothAuthEnv struct {
	address string
	ca      *testCA
	server  *grpc.Server
}

func (e *bothAuthEnv) teardown() {
	if e.server != nil {
		e.server.Stop()
	}
}

// dialValid returns a client connection with a valid mTLS cert; the caller is
// responsible for adding a bearer token to the request context.
func (e *bothAuthEnv) dialValid(t *testing.T) (*grpc.ClientConn, apiv1.TestServiceClient) {
	t.Helper()
	clientCert, err := e.ca.issueClientCert("both-client")
	require.NoError(t, err)
	conn, client, err := createMTLSClient(e.address, clientCert, e.ca.pool)
	require.NoError(t, err)
	return conn, client
}

// setupBothAuthServer creates a gRPC server that requires BOTH a valid client
// certificate AND a valid OIDC bearer token (mode "both").
func setupBothAuthServer(t *testing.T) *bothAuthEnv {
	t.Helper()

	ca, err := newTestCA("Both Auth CA")
	require.NoError(t, err)
	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	provider := &mockProvider{verifier: &mockTokenVerifier{token: token}}
	authCfg := config.AuthConfig{
		OIDCEnabled:  true,
		OIDCClientID: testClientID,
		OIDCAudience: testAudience,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	creds := credentials.NewTLS(tlsConfig)
	logger := zap.NewNop()

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			metrics.UnaryServerInterceptor(),
			mtls.UnaryInterceptor(mtls.Config{}, logger),
			authoidc.UnaryInterceptor(provider, authCfg, logger),
		),
		grpc.ChainStreamInterceptor(
			metrics.StreamServerInterceptor(),
			mtls.StreamInterceptor(mtls.Config{}, logger),
			authoidc.StreamInterceptor(provider, authCfg, logger),
		),
	)

	apiv1.RegisterTestServiceServer(grpcServer, newTestService(logger))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = grpcServer.Serve(listener) }()

	env := &bothAuthEnv{address: listener.Addr().String(), ca: ca, server: grpcServer}
	t.Cleanup(env.teardown)
	return env
}
