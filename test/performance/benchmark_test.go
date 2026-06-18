//go:build performance

package performance

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/grpc-example/internal/metrics"
	"github.com/vyrodovalexey/grpc-example/internal/telemetry"
	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

func BenchmarkInsecure_UnaryRPC(b *testing.B) {
	address, cleanup := insecureServer(b)
	defer cleanup()

	conn, client := insecureClient(b, address)
	defer conn.Close()

	ctx := context.Background()
	req := &apiv1.UnaryRequest{Message: "benchmark"}

	// Warm up.
	for range 10 {
		_, _ = client.Unary(ctx, req)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := client.Unary(ctx, req)
		if err != nil {
			b.Fatalf("unary call failed: %v", err)
		}
	}
}

func BenchmarkTLS_UnaryRPC(b *testing.B) {
	ca, err := newBenchCA()
	if err != nil {
		b.Fatalf("create CA: %v", err)
	}

	address, cleanup := tlsServer(b, ca)
	defer cleanup()

	conn, client := tlsClient(b, address, ca.pool)
	defer conn.Close()

	ctx := context.Background()
	req := &apiv1.UnaryRequest{Message: "benchmark"}

	// Warm up.
	for range 10 {
		_, _ = client.Unary(ctx, req)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := client.Unary(ctx, req)
		if err != nil {
			b.Fatalf("unary call failed: %v", err)
		}
	}
}

func BenchmarkMTLS_UnaryRPC(b *testing.B) {
	ca, err := newBenchCA()
	if err != nil {
		b.Fatalf("create CA: %v", err)
	}

	address, cleanup := mtlsServer(b, ca)
	defer cleanup()

	clientCert, err := ca.issueCert("bench-client", nil, nil)
	if err != nil {
		b.Fatalf("issue client cert: %v", err)
	}

	conn, client := mtlsClient(b, address, clientCert, ca.pool)
	defer conn.Close()

	ctx := context.Background()
	req := &apiv1.UnaryRequest{Message: "benchmark"}

	// Warm up.
	for range 10 {
		_, _ = client.Unary(ctx, req)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := client.Unary(ctx, req)
		if err != nil {
			b.Fatalf("unary call failed: %v", err)
		}
	}
}

func BenchmarkOIDC_UnaryRPC(b *testing.B) {
	address, cleanup := oidcServer(b)
	defer cleanup()

	conn, client := insecureClient(b, address)
	defer conn.Close()

	ctx := contextWithBearerToken(context.Background(), "bench-token")
	req := &apiv1.UnaryRequest{Message: "benchmark"}

	// Warm up.
	for range 10 {
		_, _ = client.Unary(ctx, req)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := client.Unary(ctx, req)
		if err != nil {
			b.Fatalf("unary call failed: %v", err)
		}
	}
}

func BenchmarkBoth_UnaryRPC(b *testing.B) {
	ca, err := newBenchCA()
	if err != nil {
		b.Fatalf("create CA: %v", err)
	}

	address, cleanup := bothServer(b, ca)
	defer cleanup()

	clientCert, err := ca.issueCert("bench-client", nil, nil)
	if err != nil {
		b.Fatalf("issue client cert: %v", err)
	}

	conn, client := mtlsClient(b, address, clientCert, ca.pool)
	defer conn.Close()

	ctx := contextWithBearerToken(context.Background(), "bench-token")
	req := &apiv1.UnaryRequest{Message: "benchmark"}

	// Warm up.
	for range 10 {
		_, _ = client.Unary(ctx, req)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := client.Unary(ctx, req)
		if err != nil {
			b.Fatalf("unary call failed: %v", err)
		}
	}
}

func BenchmarkTLSHandshake(b *testing.B) {
	ca, err := newBenchCA()
	if err != nil {
		b.Fatalf("create CA: %v", err)
	}

	serverCert, err := ca.issueCert("bench-server", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatalf("issue server cert: %v", err)
	}

	// Start a raw TLS listener.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	address := lis.Addr().String()

	// Accept connections in background.
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, tlsConfig)
			go func() {
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}()
		}
	}()

	clientTLSConfig := &tls.Config{
		RootCAs:    ca.pool,
		MinVersion: tls.VersionTLS12,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		conn, err := tls.Dial("tcp", address, clientTLSConfig)
		if err != nil {
			b.Fatalf("TLS dial failed: %v", err)
		}
		conn.Close()
	}
}

func BenchmarkMTLSHandshake(b *testing.B) {
	ca, err := newBenchCA()
	if err != nil {
		b.Fatalf("create CA: %v", err)
	}

	serverCert, err := ca.issueCert("bench-server", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatalf("issue server cert: %v", err)
	}

	clientCert, err := ca.issueCert("bench-client", nil, nil)
	if err != nil {
		b.Fatalf("issue client cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	address := lis.Addr().String()

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, tlsConfig)
			go func() {
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}()
		}
	}()

	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.pool,
		MinVersion:   tls.VersionTLS12,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		conn, err := tls.Dial("tcp", address, clientTLSConfig)
		if err != nil {
			b.Fatalf("mTLS dial failed: %v", err)
		}
		conn.Close()
	}
}

func BenchmarkTokenValidationOverhead(b *testing.B) {
	// Benchmark the overhead of OIDC token validation vs no auth.
	b.Run("no_auth", func(b *testing.B) {
		address, cleanup := insecureServer(b)
		defer cleanup()

		conn, client := insecureClient(b, address)
		defer conn.Close()

		ctx := context.Background()
		req := &apiv1.UnaryRequest{Message: "benchmark"}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_, err := client.Unary(ctx, req)
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("with_oidc", func(b *testing.B) {
		address, cleanup := oidcServer(b)
		defer cleanup()

		conn, client := insecureClient(b, address)
		defer conn.Close()

		ctx := contextWithBearerToken(context.Background(), "bench-token")
		req := &apiv1.UnaryRequest{Message: "benchmark"}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_, err := client.Unary(ctx, req)
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})
}

func BenchmarkAuthModes_Comparison(b *testing.B) {
	ca, err := newBenchCA()
	if err != nil {
		b.Fatalf("create CA: %v", err)
	}

	clientCert, err := ca.issueCert("bench-client", nil, nil)
	if err != nil {
		b.Fatalf("issue client cert: %v", err)
	}

	b.Run("insecure", func(b *testing.B) {
		address, cleanup := insecureServer(b)
		defer cleanup()

		conn, client := insecureClient(b, address)
		defer conn.Close()

		ctx := context.Background()
		req := &apiv1.UnaryRequest{Message: "benchmark"}

		b.ResetTimer()
		for b.Loop() {
			_, _ = client.Unary(ctx, req)
		}
	})

	b.Run("tls", func(b *testing.B) {
		address, cleanup := tlsServer(b, ca)
		defer cleanup()

		conn, client := tlsClient(b, address, ca.pool)
		defer conn.Close()

		ctx := context.Background()
		req := &apiv1.UnaryRequest{Message: "benchmark"}

		b.ResetTimer()
		for b.Loop() {
			_, _ = client.Unary(ctx, req)
		}
	})

	b.Run("mtls", func(b *testing.B) {
		address, cleanup := mtlsServer(b, ca)
		defer cleanup()

		conn, client := mtlsClient(b, address, clientCert, ca.pool)
		defer conn.Close()

		ctx := context.Background()
		req := &apiv1.UnaryRequest{Message: "benchmark"}

		b.ResetTimer()
		for b.Loop() {
			_, _ = client.Unary(ctx, req)
		}
	})

	b.Run("oidc", func(b *testing.B) {
		address, cleanup := oidcServer(b)
		defer cleanup()

		conn, client := insecureClient(b, address)
		defer conn.Close()

		ctx := contextWithBearerToken(context.Background(), "bench-token")
		req := &apiv1.UnaryRequest{Message: "benchmark"}

		b.ResetTimer()
		for b.Loop() {
			_, _ = client.Unary(ctx, req)
		}
	})

	b.Run("both", func(b *testing.B) {
		address, cleanup := bothServer(b, ca)
		defer cleanup()

		conn, client := mtlsClient(b, address, clientCert, ca.pool)
		defer conn.Close()

		ctx := contextWithBearerToken(context.Background(), "bench-token")
		req := &apiv1.UnaryRequest{Message: "benchmark"}

		b.ResetTimer()
		for b.Loop() {
			_, _ = client.Unary(ctx, req)
		}
	})
}

// ---------------------------------------------------------------------------
// Observability overhead benchmarks
//
// These quantify the cost of the additive Prometheus metric interceptors,
// stream message counters, auth-attempt instrumentation, and gated OTLP export
// so regressions in the hot path can be detected and budgeted.
// ---------------------------------------------------------------------------

// metricsUnaryServer creates an insecure gRPC server with an optional unary
// metrics interceptor installed.
func metricsUnaryServer(b *testing.B, withMetrics bool) (string, func()) {
	b.Helper()

	var opts []grpc.ServerOption
	if withMetrics {
		opts = append(opts, grpc.ChainUnaryInterceptor(metrics.UnaryServerInterceptor()))
	}
	srv := grpc.NewServer(opts...)
	apiv1.RegisterTestServiceServer(srv, &benchTestService{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	return lis.Addr().String(), srv.Stop
}

// BenchmarkMetricsOverhead compares unary RPC latency/allocs with and without
// the Prometheus metric interceptor.
func BenchmarkMetricsOverhead(b *testing.B) {
	run := func(b *testing.B, withMetrics bool) {
		address, cleanup := metricsUnaryServer(b, withMetrics)
		defer cleanup()

		conn, client := insecureClient(b, address)
		defer conn.Close()

		ctx := context.Background()
		req := &apiv1.UnaryRequest{Message: "benchmark"}
		for range 10 {
			_, _ = client.Unary(ctx, req)
		}

		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			if _, err := client.Unary(ctx, req); err != nil {
				b.Fatalf("unary call failed: %v", err)
			}
		}
	}

	b.Run("disabled", func(b *testing.B) { run(b, false) })
	b.Run("enabled", func(b *testing.B) { run(b, true) })
}

// BenchmarkStreamMetricsOverhead measures server-streaming RPC throughput with
// the stream metrics interceptor (msg sent/received counters) installed.
func BenchmarkStreamMetricsOverhead(b *testing.B) {
	run := func(b *testing.B, withMetrics bool) {
		address, cleanup := streamServer(b, withMetrics)
		defer cleanup()

		conn, client := insecureClient(b, address)
		defer conn.Close()

		req := &apiv1.StreamRequest{Count: 10}
		drain := func() {
			stream, err := client.ServerStream(context.Background(), req)
			if err != nil {
				b.Fatalf("server stream: %v", err)
			}
			for {
				_, recvErr := stream.Recv()
				if recvErr == io.EOF {
					return
				}
				if recvErr != nil {
					b.Fatalf("recv: %v", recvErr)
				}
			}
		}

		drain() // warm up
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			drain()
		}
	}

	b.Run("disabled", func(b *testing.B) { run(b, false) })
	b.Run("enabled", func(b *testing.B) { run(b, true) })
}

// BenchmarkAuthMetricsOverhead measures the cost of recording an auth attempt
// (auth_attempts_total counter + auth_attempt_duration_seconds histogram).
func BenchmarkAuthMetricsOverhead(b *testing.B) {
	b.Run("mtls", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			metrics.RecordAuthAttempt(metrics.AuthTypeMTLS, true, 250*time.Microsecond)
		}
	})
	b.Run("oidc", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			metrics.RecordAuthAttempt(metrics.AuthTypeOIDC, true, 250*time.Microsecond)
		}
	})
}

// BenchmarkOTLP measures unary RPC latency with the OTLP metrics export pipeline
// disabled vs. enabled (gated). The Prometheus metric interceptor is always
// installed so the difference isolates the OTLP push pipeline overhead.
func BenchmarkOTLP(b *testing.B) {
	logger := zap.NewNop()

	run := func(b *testing.B) {
		address, cleanup := metricsUnaryServer(b, true)
		defer cleanup()

		conn, client := insecureClient(b, address)
		defer conn.Close()

		ctx := context.Background()
		req := &apiv1.UnaryRequest{Message: "benchmark"}
		for range 10 {
			_, _ = client.Unary(ctx, req)
		}

		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			if _, err := client.Unary(ctx, req); err != nil {
				b.Fatalf("unary call failed: %v", err)
			}
		}
	}

	b.Run("disabled", func(b *testing.B) {
		telemetry.ShutdownMeterProvider(logger)
		run(b)
	})

	b.Run("enabled", func(b *testing.B) {
		// The OTLP HTTP exporter dials lazily and exports on a background
		// interval, so init never blocks even if no collector is listening.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := telemetry.InitMeterProvider(ctx,
			telemetry.Config{Enabled: true, Endpoint: "localhost:4318", ServiceName: "perf-otlp"}, logger)
		cancel()
		if err != nil {
			b.Fatalf("init meter provider: %v", err)
		}
		b.Cleanup(func() { telemetry.ShutdownMeterProvider(logger) })
		run(b)
	})
}

// BenchmarkNewConnection measures the cost of establishing new connections.
func BenchmarkNewConnection_Insecure(b *testing.B) {
	address, cleanup := insecureServer(b)
	defer cleanup()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		conn, client := insecureClient(b, address)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = client.Unary(ctx, &apiv1.UnaryRequest{Message: "bench"})
		cancel()
		conn.Close()
	}
}

func BenchmarkNewConnection_MTLS(b *testing.B) {
	ca, err := newBenchCA()
	if err != nil {
		b.Fatalf("create CA: %v", err)
	}

	address, cleanup := mtlsServer(b, ca)
	defer cleanup()

	clientCert, err := ca.issueCert("bench-client", nil, nil)
	if err != nil {
		b.Fatalf("issue client cert: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		conn, client := mtlsClient(b, address, clientCert, ca.pool)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = client.Unary(ctx, &apiv1.UnaryRequest{Message: "bench"})
		cancel()
		conn.Close()
	}
}
