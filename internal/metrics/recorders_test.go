package metrics_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/grpc-example/internal/metrics"
)

// errStreamFailure is a sentinel error used to exercise the failure paths of the
// monitored stream wrapper without coupling tests to gRPC status semantics.
var errStreamFailure = errors.New("stream failure")

func TestRecordAuthAttempt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		authType string
		success  bool
		duration time.Duration
		result   string
	}{
		{
			name:     "successful mtls attempt",
			authType: metrics.AuthTypeMTLS,
			success:  true,
			duration: 5 * time.Millisecond,
			result:   metrics.ResultSuccess,
		},
		{
			name:     "failed mtls attempt",
			authType: metrics.AuthTypeMTLS,
			success:  false,
			duration: 2 * time.Millisecond,
			result:   metrics.ResultFailure,
		},
		{
			name:     "successful oidc attempt",
			authType: metrics.AuthTypeOIDC,
			success:  true,
			duration: 7 * time.Millisecond,
			result:   metrics.ResultSuccess,
		},
		{
			name:     "failed oidc attempt with zero duration",
			authType: metrics.AuthTypeOIDC,
			success:  false,
			duration: 0,
			result:   metrics.ResultFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange - capture the baseline counter value for this label set.
			counter := metrics.AuthAttemptsTotal.WithLabelValues(tt.authType, tt.result)
			before := testutil.ToFloat64(counter)

			// Act
			metrics.RecordAuthAttempt(tt.authType, tt.success, tt.duration)

			// Assert - the specific labelled counter increased by exactly one,
			// and the duration histogram registered an observation.
			assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9)
			assert.Positive(t, testutil.CollectAndCount(metrics.AuthAttemptDurationSeconds))
		})
	}
}

func TestRecordVaultPKIOperation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation string
		success   bool
		duration  time.Duration
		result    string
	}{
		{
			name:      "successful issue_certificate",
			operation: "issue_certificate",
			success:   true,
			duration:  10 * time.Millisecond,
			result:    metrics.ResultSuccess,
		},
		{
			name:      "failed issue_certificate",
			operation: "issue_certificate",
			success:   false,
			duration:  3 * time.Millisecond,
			result:    metrics.ResultFailure,
		},
		{
			name:      "successful get_ca_certificate",
			operation: "get_ca_certificate",
			success:   true,
			duration:  1 * time.Millisecond,
			result:    metrics.ResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			counter := metrics.VaultPKIOperationsTotal.WithLabelValues(tt.operation, tt.result)
			before := testutil.ToFloat64(counter)

			// Act
			metrics.RecordVaultPKIOperation(tt.operation, tt.success, tt.duration)

			// Assert
			assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9)
			assert.Positive(t, testutil.CollectAndCount(metrics.VaultPKIOperationDurationSeconds))
		})
	}
}

func TestRecordOIDCVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		success bool
		result  string
	}{
		{
			name:    "successful verification",
			success: true,
			result:  metrics.ResultSuccess,
		},
		{
			name:    "failed verification",
			success: false,
			result:  metrics.ResultFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			counter := metrics.OIDCVerificationTotal.WithLabelValues(tt.result)
			before := testutil.ToFloat64(counter)

			// Act
			metrics.RecordOIDCVerification(tt.success)

			// Assert
			assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9)
		})
	}
}

func TestRecordOIDCProviderRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation string
		success   bool
		result    string
	}{
		{
			name:      "successful discovery",
			operation: "discovery",
			success:   true,
			result:    metrics.ResultSuccess,
		},
		{
			name:      "failed discovery",
			operation: "discovery",
			success:   false,
			result:    metrics.ResultFailure,
		},
		{
			name:      "successful health_check",
			operation: "health_check",
			success:   true,
			result:    metrics.ResultSuccess,
		},
		{
			name:      "failed health_check",
			operation: "health_check",
			success:   false,
			result:    metrics.ResultFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			counter := metrics.OIDCProviderRequestsTotal.WithLabelValues(tt.operation, tt.result)
			before := testutil.ToFloat64(counter)

			// Act
			metrics.RecordOIDCProviderRequest(tt.operation, tt.success)

			// Assert
			assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9)
		})
	}
}

func TestNewRecorderMetricsRegistered(t *testing.T) {
	t.Parallel()

	// Arrange - touch each new metric so it is exposed by the default gatherer.
	metrics.RecordAuthAttempt(metrics.AuthTypeMTLS, true, time.Millisecond)
	metrics.RecordVaultPKIOperation("issue_certificate", true, time.Millisecond)
	metrics.RecordOIDCVerification(true)
	metrics.RecordOIDCProviderRequest("discovery", true)
	metrics.ServerInFlightRequests.WithLabelValues("unary", "svc", "M").Inc()
	metrics.ServerMsgReceivedTotal.WithLabelValues("server_stream", "svc", "M").Inc()
	metrics.ServerMsgSentTotal.WithLabelValues("server_stream", "svc", "M").Inc()

	// Act & Assert - each new metric reports at least one series.
	assert.Positive(t, testutil.CollectAndCount(metrics.AuthAttemptDurationSeconds))
	assert.Positive(t, testutil.CollectAndCount(metrics.VaultPKIOperationsTotal))
	assert.Positive(t, testutil.CollectAndCount(metrics.VaultPKIOperationDurationSeconds))
	assert.Positive(t, testutil.CollectAndCount(metrics.OIDCVerificationTotal))
	assert.Positive(t, testutil.CollectAndCount(metrics.OIDCProviderRequestsTotal))
	assert.Positive(t, testutil.CollectAndCount(metrics.ServerInFlightRequests))
	assert.Positive(t, testutil.CollectAndCount(metrics.ServerMsgReceivedTotal))
	assert.Positive(t, testutil.CollectAndCount(metrics.ServerMsgSentTotal))
}

// countingServerStream is a grpc.ServerStream test double whose SendMsg and RecvMsg
// return configurable errors so we can exercise both success and failure paths of
// the monitored stream wrapper used by StreamServerInterceptor.
type countingServerStream struct {
	grpc.ServerStream
	sendErr error
	recvErr error
}

func (c *countingServerStream) SendMsg(any) error { return c.sendErr }
func (c *countingServerStream) RecvMsg(any) error { return c.recvErr }

func TestStreamServerInterceptor_MessageCounters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		errs            recvSend
		method          string
		wantSentDelta   float64
		wantRecvedDelta float64
	}{
		{
			name:            "successful send and receive increment counters",
			errs:            recvSend{send: nil, recv: nil},
			method:          "/msgcount.Service/OkMethod",
			wantSentDelta:   1,
			wantRecvedDelta: 1,
		},
		{
			name:            "failed send does not increment sent counter",
			errs:            recvSend{send: errStreamFailure, recv: nil},
			method:          "/msgcount.Service/SendFailMethod",
			wantSentDelta:   0,
			wantRecvedDelta: 1,
		},
		{
			name:            "failed receive does not increment received counter",
			errs:            recvSend{send: nil, recv: errStreamFailure},
			method:          "/msgcount.Service/RecvFailMethod",
			wantSentDelta:   1,
			wantRecvedDelta: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			interceptor := metrics.StreamServerInterceptor()
			info := &grpc.StreamServerInfo{
				FullMethod:     tt.method,
				IsServerStream: true,
			}
			inner := &countingServerStream{sendErr: tt.errs.send, recvErr: tt.errs.recv}

			method := methodOf(tt.method)
			sentCounter := metrics.ServerMsgSentTotal.WithLabelValues("server_stream", "msgcount.Service", method)
			recvCounter := metrics.ServerMsgReceivedTotal.WithLabelValues("server_stream", "msgcount.Service", method)
			sentBefore := testutil.ToFloat64(sentCounter)
			recvBefore := testutil.ToFloat64(recvCounter)

			handler := func(_ any, ss grpc.ServerStream) error {
				// Exercise the wrapped SendMsg / RecvMsg paths.
				_ = ss.SendMsg("payload")
				_ = ss.RecvMsg(new(string))
				return nil
			}

			// Act
			err := interceptor(nil, inner, info, handler)

			// Assert
			require.NoError(t, err)
			assert.InDelta(t, sentBefore+tt.wantSentDelta, testutil.ToFloat64(sentCounter), 1e-9)
			assert.InDelta(t, recvBefore+tt.wantRecvedDelta, testutil.ToFloat64(recvCounter), 1e-9)
		})
	}
}

// recvSend bundles the configurable send/recv errors for a table row.
type recvSend struct {
	send error
	recv error
}

// methodOf extracts the method component of a "/svc/method" full method name.
func methodOf(fullMethod string) string {
	for i := len(fullMethod) - 1; i >= 0; i-- {
		if fullMethod[i] == '/' {
			return fullMethod[i+1:]
		}
	}
	return fullMethod
}

func TestUnaryServerInterceptor_InFlightGauge(t *testing.T) {
	t.Parallel()

	// Arrange - the in-flight gauge must return to its starting value after the
	// handler completes (incremented on entry, decremented via defer on exit).
	interceptor := metrics.UnaryServerInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/inflight.Service/Method"}
	gauge := metrics.ServerInFlightRequests.WithLabelValues("unary", "inflight.Service", "Method")
	before := testutil.ToFloat64(gauge)

	var inFlightDuringHandler float64
	handler := func(_ context.Context, _ any) (any, error) {
		inFlightDuringHandler = testutil.ToFloat64(gauge)
		return "ok", nil
	}

	// Act
	resp, err := interceptor(context.Background(), nil, info, handler)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.InDelta(t, before+1, inFlightDuringHandler, 1e-9, "gauge should be incremented while handler runs")
	assert.InDelta(t, before, testutil.ToFloat64(gauge), 1e-9, "gauge should return to baseline after handler")
}
