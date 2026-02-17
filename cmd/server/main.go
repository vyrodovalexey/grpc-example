// Package main provides the entry point for the gRPC test server.
package main

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"os/signal"
	"syscall"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
	authoidc "github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
	"github.com/vyrodovalexey/grpc-example/internal/logger"
	"github.com/vyrodovalexey/grpc-example/internal/metrics"
	"github.com/vyrodovalexey/grpc-example/internal/server"
	"github.com/vyrodovalexey/grpc-example/internal/service"
	"github.com/vyrodovalexey/grpc-example/internal/telemetry"
	tlspkg "github.com/vyrodovalexey/grpc-example/internal/tls"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		// Use basic logger for startup errors
		basicLogger := zap.Must(zap.NewProduction())
		basicLogger.Fatal("failed to load configuration", zap.Error(err))
	}

	// Initialize logger
	log, err := logger.InitLogger(cfg.LogLevel)
	if err != nil {
		basicLogger := zap.Must(zap.NewProduction())
		basicLogger.Fatal("failed to initialize logger", zap.Error(err))
	}
	log.Info("starting gRPC test server", zap.String("config", cfg.String()))

	if runErr := run(cfg, log); runErr != nil {
		log.Fatal("server error", zap.Error(runErr))
	}

	log.Info("server shutdown complete")
	logger.SyncLogger(log)
}

// run executes the main server lifecycle with proper resource cleanup via defers.
func run(cfg *config.Config, log *zap.Logger) error {
	// Setup signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Initialize OpenTelemetry tracer.
	if initErr := telemetry.InitTracer(ctx, telemetry.Config{
		Enabled:     cfg.OTEL.Enabled,
		Endpoint:    cfg.OTEL.Endpoint,
		ServiceName: cfg.OTEL.ServiceName,
	}, log); initErr != nil {
		return fmt.Errorf("initializing tracer: %w", initErr)
	}
	defer telemetry.ShutdownTracer(log)

	// Start metrics HTTP server.
	metricsSrv := metrics.NewServer(cfg.MetricsPort, log)
	metricsSrv.Start()
	defer metricsSrv.Shutdown()

	// Build server options (TLS, auth interceptors, metrics, telemetry).
	opts, err := buildServerOptions(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("building server options: %w", err)
	}

	// Create service
	testService := service.NewTestService(log)

	// Create server with options
	srv := server.NewServer(server.Config{
		Address:          cfg.GRPCAddress(),
		ShutdownTimeout:  cfg.ShutdownTimeout,
		EnableReflection: cfg.EnableReflection,
	}, testService, log, opts...)

	// Start server (blocks until shutdown)
	return srv.Start(ctx)
}

// buildServerOptions constructs gRPC server options based on configuration.
func buildServerOptions(ctx context.Context, cfg *config.Config, log *zap.Logger) ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var streamInterceptors []grpc.StreamServerInterceptor

	// Add OpenTelemetry stats handler for distributed tracing.
	opts = append(opts, grpc.StatsHandler(otelgrpc.NewServerHandler()))

	// Add Prometheus metrics interceptors.
	unaryInterceptors = append(unaryInterceptors, metrics.UnaryServerInterceptor())
	streamInterceptors = append(streamInterceptors, metrics.StreamServerInterceptor())

	// Configure TLS if enabled.
	if cfg.TLS.Enabled {
		tlsOpts, err := buildTLSOptions(ctx, cfg, log)
		if err != nil {
			return nil, err
		}
		opts = append(opts, tlsOpts...)
		log.Info("TLS enabled", zap.String("mode", cfg.TLS.Mode))
	} else {
		log.Info("TLS disabled, running in insecure mode")
	}

	// Configure auth interceptors based on auth mode.
	switch cfg.Auth.Mode {
	case config.AuthModeMTLS:
		mtlsCfg := mtls.Config{}
		unaryInterceptors = append(unaryInterceptors, mtls.UnaryInterceptor(mtlsCfg, log))
		streamInterceptors = append(streamInterceptors, mtls.StreamInterceptor(mtlsCfg, log))
		log.Info("mTLS authentication enabled")

	case config.AuthModeOIDC:
		oidcInterceptors, err := buildOIDCInterceptors(ctx, cfg, log)
		if err != nil {
			return nil, err
		}
		unaryInterceptors = append(unaryInterceptors, oidcInterceptors.unary)
		streamInterceptors = append(streamInterceptors, oidcInterceptors.stream)
		log.Info("OIDC authentication enabled")

	case config.AuthModeBoth:
		mtlsCfg := mtls.Config{}
		unaryInterceptors = append(unaryInterceptors, mtls.UnaryInterceptor(mtlsCfg, log))
		streamInterceptors = append(streamInterceptors, mtls.StreamInterceptor(mtlsCfg, log))

		oidcInterceptors, err := buildOIDCInterceptors(ctx, cfg, log)
		if err != nil {
			return nil, err
		}
		unaryInterceptors = append(unaryInterceptors, oidcInterceptors.unary)
		streamInterceptors = append(streamInterceptors, oidcInterceptors.stream)
		log.Info("mTLS + OIDC authentication enabled")

	default:
		log.Info("no authentication enabled", zap.String("auth_mode", cfg.Auth.Mode))
	}

	// Chain interceptors.
	opts = append(opts,
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	)

	return opts, nil
}

// buildTLSOptions constructs TLS-related gRPC server options.
func buildTLSOptions(
	ctx context.Context,
	cfg *config.Config,
	log *zap.Logger,
) ([]grpc.ServerOption, error) {
	// If Vault is enabled, load certificates from Vault.
	if cfg.TLS.VaultEnabled {
		return buildVaultTLSOptions(ctx, cfg, log)
	}

	// Load certificates from files.
	tlsConfig, err := tlspkg.BuildServerTLSConfig(cfg.TLS)
	if err != nil {
		return nil, err
	}

	log.Info("loaded TLS certificates from files",
		zap.String("cert", cfg.TLS.CertPath),
		zap.String("key", cfg.TLS.KeyPath),
	)

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

// buildVaultTLSOptions loads TLS certificates from Vault and constructs server options.
func buildVaultTLSOptions(
	ctx context.Context,
	cfg *config.Config,
	log *zap.Logger,
) ([]grpc.ServerOption, error) {
	vaultClient, err := tlspkg.NewVaultPKIClient(cfg.TLS, log)
	if err != nil {
		return nil, fmt.Errorf("creating vault PKI client: %w", err)
	}

	cert, caPEM, err := vaultClient.IssueCertificate(ctx, "grpc-server")
	if err != nil {
		return nil, fmt.Errorf("issuing certificate from vault: %w", err)
	}

	tlsConfig := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{cert},
		MinVersion:   cryptotls.VersionTLS12,
	}

	if cfg.TLS.Mode == config.TLSModeMTLS && caPEM != "" {
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("failed to parse CA certificate PEM from vault")
		}
		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = cryptotls.RequireAndVerifyClientCert
	}

	log.Info("loaded TLS certificates from Vault")
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

// oidcInterceptorPair holds both unary and stream OIDC interceptors.
type oidcInterceptorPair struct {
	unary  grpc.UnaryServerInterceptor
	stream grpc.StreamServerInterceptor
}

// buildOIDCInterceptors creates OIDC interceptors from configuration.
func buildOIDCInterceptors(
	ctx context.Context,
	cfg *config.Config,
	log *zap.Logger,
) (*oidcInterceptorPair, error) {
	provider, err := authoidc.NewProvider(ctx, cfg.Auth, log)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider: %w", err)
	}

	return &oidcInterceptorPair{
		unary:  authoidc.UnaryInterceptor(provider, cfg.Auth, log),
		stream: authoidc.StreamInterceptor(provider, cfg.Auth, log),
	}, nil
}
