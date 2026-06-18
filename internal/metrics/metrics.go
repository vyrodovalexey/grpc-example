// Package metrics provides Prometheus metrics and a metrics HTTP server for the gRPC server.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "grpc"
	metricsSubsystem = "server"

	// Metric label names.
	labelGRPCType    = "grpc_type"
	labelGRPCService = "grpc_service"
	labelGRPCMethod  = "grpc_method"
	labelGRPCCode    = "grpc_code"

	// Auth and external-dependency label names.
	labelAuthType  = "auth_type"
	labelResult    = "result"
	labelOperation = "operation"

	// ResultSuccess marks a successful operation/auth attempt.
	ResultSuccess = "success"
	// ResultFailure marks a failed operation/auth attempt.
	ResultFailure = "failure"

	// AuthTypeMTLS identifies mTLS authentication attempts.
	AuthTypeMTLS = "mtls"
	// AuthTypeOIDC identifies OIDC authentication attempts.
	AuthTypeOIDC = "oidc"
)

// gRPC server metrics.
var (
	// ServerStartedTotal counts the total number of RPCs started on the server.
	ServerStartedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "started_total",
			Help:      "Total number of RPCs started on the server.",
		},
		[]string{labelGRPCType, labelGRPCService, labelGRPCMethod},
	)

	// ServerHandledTotal counts the total number of RPCs completed on the server, regardless of success or failure.
	ServerHandledTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "handled_total",
			Help:      "Total number of RPCs completed on the server, regardless of success or failure.",
		},
		[]string{labelGRPCType, labelGRPCService, labelGRPCMethod, labelGRPCCode},
	)

	// ServerHandlingSeconds is a histogram of response latency (seconds) of gRPC that had been
	// application-level handled by the server.
	ServerHandlingSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "handling_seconds",
			Help:      "Histogram of response latency (seconds) of gRPC handled by the server.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{labelGRPCType, labelGRPCService, labelGRPCMethod},
	)

	// ServerInFlightRequests tracks the number of in-flight (currently executing) RPCs on the server.
	ServerInFlightRequests = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "in_flight_requests",
			Help:      "Number of RPCs currently being handled by the server.",
		},
		[]string{labelGRPCType, labelGRPCService, labelGRPCMethod},
	)

	// ServerMsgReceivedTotal counts the total number of stream messages received by the server.
	ServerMsgReceivedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "msg_received_total",
			Help:      "Total number of stream messages received by the server.",
		},
		[]string{labelGRPCType, labelGRPCService, labelGRPCMethod},
	)

	// ServerMsgSentTotal counts the total number of stream messages sent by the server.
	ServerMsgSentTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "msg_sent_total",
			Help:      "Total number of stream messages sent by the server.",
		},
		[]string{labelGRPCType, labelGRPCService, labelGRPCMethod},
	)

	// AuthAttemptsTotal counts the total number of authentication attempts.
	AuthAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts.",
		},
		[]string{labelAuthType, labelResult},
	)

	// AuthAttemptDurationSeconds is a histogram of authentication attempt latency in seconds.
	AuthAttemptDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_attempt_duration_seconds",
			Help:    "Histogram of authentication attempt latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{labelAuthType, labelResult},
	)

	// VaultPKIOperationsTotal counts Vault PKI operations by operation name and result.
	VaultPKIOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vault_pki_operations_total",
			Help: "Total number of Vault PKI operations by operation and result.",
		},
		[]string{labelOperation, labelResult},
	)

	// VaultPKIOperationDurationSeconds is a histogram of Vault PKI operation latency in seconds.
	VaultPKIOperationDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "vault_pki_operation_duration_seconds",
			Help:    "Histogram of Vault PKI operation latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{labelOperation},
	)

	// OIDCVerificationTotal counts OIDC token verification attempts by result.
	OIDCVerificationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oidc_verification_total",
			Help: "Total number of OIDC token verifications by result.",
		},
		[]string{labelResult},
	)

	// OIDCProviderRequestsTotal counts OIDC provider requests (discovery/JWKS/health) by operation and result.
	OIDCProviderRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oidc_provider_requests_total",
			Help: "Total number of OIDC provider requests by operation and result.",
		},
		[]string{labelOperation, labelResult},
	)
)

// resultLabel maps a boolean success flag to the canonical result label value.
func resultLabel(success bool) string {
	if success {
		return ResultSuccess
	}
	return ResultFailure
}

// RecordAuthAttempt records an authentication attempt for the given auth type, including
// the success/failure outcome and the observed latency. It increments AuthAttemptsTotal
// and observes AuthAttemptDurationSeconds. This is the single wiring point used by the
// mTLS and OIDC interceptors to avoid an import cycle on the metrics package internals.
func RecordAuthAttempt(authType string, success bool, duration time.Duration) {
	result := resultLabel(success)
	AuthAttemptsTotal.WithLabelValues(authType, result).Inc()
	AuthAttemptDurationSeconds.WithLabelValues(authType, result).Observe(duration.Seconds())
}

// RecordVaultPKIOperation records a Vault PKI operation outcome and latency for the given
// operation name (for example "issue_certificate" or "get_ca_certificate").
func RecordVaultPKIOperation(operation string, success bool, duration time.Duration) {
	VaultPKIOperationsTotal.WithLabelValues(operation, resultLabel(success)).Inc()
	VaultPKIOperationDurationSeconds.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordOIDCVerification records the outcome of a single OIDC token verification.
func RecordOIDCVerification(success bool) {
	OIDCVerificationTotal.WithLabelValues(resultLabel(success)).Inc()
}

// RecordOIDCProviderRequest records an OIDC provider request outcome for the given
// operation name (for example "discovery" or "health_check").
func RecordOIDCProviderRequest(operation string, success bool) {
	OIDCProviderRequestsTotal.WithLabelValues(operation, resultLabel(success)).Inc()
}
