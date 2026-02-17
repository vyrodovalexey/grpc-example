// Package metrics provides Prometheus metrics and a metrics HTTP server for the gRPC server.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "grpc"
	metricsSubsystem = "server"
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
		[]string{"grpc_type", "grpc_service", "grpc_method"},
	)

	// ServerHandledTotal counts the total number of RPCs completed on the server, regardless of success or failure.
	ServerHandledTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "handled_total",
			Help:      "Total number of RPCs completed on the server, regardless of success or failure.",
		},
		[]string{"grpc_type", "grpc_service", "grpc_method", "grpc_code"},
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
		[]string{"grpc_type", "grpc_service", "grpc_method"},
	)

	// AuthAttemptsTotal counts the total number of authentication attempts.
	AuthAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts.",
		},
		[]string{"auth_type", "result"},
	)
)
