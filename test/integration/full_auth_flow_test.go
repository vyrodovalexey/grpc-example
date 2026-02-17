//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
	authoidc "github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
	tlspkg "github.com/vyrodovalexey/grpc-example/internal/tls"
	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

func TestIntegration_FullMTLSFlow_WithVaultCerts(t *testing.T) {
	skipIfVaultUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	logger := newTestLogger()

	tlsCfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	serverVaultClient, err := tlspkg.NewVaultPKIClient(tlsCfg, logger)
	require.NoError(t, err)

	// Issue server certificate using the grpc-server role.
	serverCert, caPEM, err := serverVaultClient.IssueCertificate(ctx, "grpc-server")
	require.NoError(t, err)

	// Build CA pool.
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM([]byte(caPEM)), "failed to parse CA PEM")

	// Issue client certificate using the grpc-client role.
	clientTLSCfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: "grpc-client",
		VaultPKITTL:  1 * time.Hour,
	}
	clientVaultClient, err := tlspkg.NewVaultPKIClient(clientTLSCfg, logger)
	require.NoError(t, err)

	clientCert, _, err := clientVaultClient.IssueCertificate(ctx, "grpc-client")
	require.NoError(t, err)

	// Start mTLS server.
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(serverTLSConfig)
	mtlsCfg := mtls.Config{}

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(mtls.UnaryInterceptor(mtlsCfg, logger)),
		grpc.ChainStreamInterceptor(mtls.StreamInterceptor(mtlsCfg, logger)),
	)

	testService := newIntegrationTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	// Connect with client certificate.
	// Use ServerName to match the server certificate CN since the cert
	// was issued without IP SANs for 127.0.0.1.
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "grpc-server",
		MinVersion:   tls.VersionTLS12,
	}

	clientCreds := credentials.NewTLS(clientTLSConfig)
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(clientCreds))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "vault mTLS integration"})
	require.NoError(t, err)
	assert.Equal(t, "vault mTLS integration", resp.GetMessage())
}

func TestIntegration_FullOIDCFlow_WithKeycloak(t *testing.T) {
	skipIfKeycloakUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	logger := newTestLogger()

	// Acquire token from Keycloak.
	tokenResp := acquireToken(t, testConfig.ClientID, testConfig.ClientSecret)
	require.NotEmpty(t, tokenResp.AccessToken)

	// Create OIDC provider pointing to Keycloak.
	authCfg := config.AuthConfig{
		OIDCEnabled:   true,
		OIDCIssuerURL: fmt.Sprintf("%s/realms/%s", testConfig.KeycloakURL, testConfig.KeycloakRealm),
		OIDCClientID:  testConfig.ClientID,
		OIDCAudience:  "",
	}

	provider, err := authoidc.NewProvider(ctx, authCfg, logger)
	require.NoError(t, err)

	// Start server with OIDC interceptor.
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authoidc.UnaryInterceptor(provider, authCfg, logger)),
		grpc.ChainStreamInterceptor(authoidc.StreamInterceptor(provider, authCfg, logger)),
	)

	testService := newIntegrationTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	// Connect with bearer token.
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	md := metadata.New(map[string]string{
		"authorization": "Bearer " + tokenResp.AccessToken,
	})
	oidcCtx := metadata.NewOutgoingContext(ctx, md)

	resp, err := client.Unary(oidcCtx, &apiv1.UnaryRequest{Message: "keycloak OIDC integration"})
	require.NoError(t, err)
	assert.Equal(t, "keycloak OIDC integration", resp.GetMessage())
}

func TestIntegration_FullOIDCFlow_InvalidToken(t *testing.T) {
	skipIfKeycloakUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	logger := newTestLogger()

	authCfg := config.AuthConfig{
		OIDCEnabled:   true,
		OIDCIssuerURL: fmt.Sprintf("%s/realms/%s", testConfig.KeycloakURL, testConfig.KeycloakRealm),
		OIDCClientID:  testConfig.ClientID,
		OIDCAudience:  "",
	}

	provider, err := authoidc.NewProvider(ctx, authCfg, logger)
	require.NoError(t, err)

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authoidc.UnaryInterceptor(provider, authCfg, logger)),
	)

	testService := newIntegrationTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	md := metadata.New(map[string]string{
		"authorization": "Bearer invalid-token-value",
	})
	oidcCtx := metadata.NewOutgoingContext(ctx, md)

	_, err = client.Unary(oidcCtx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)
}

func TestIntegration_CombinedAuthFlow(t *testing.T) {
	skipIfVaultUnavailable(t)
	skipIfKeycloakUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	logger := newTestLogger()

	// Setup Vault PKI.
	tlsCfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	serverVaultClient, err := tlspkg.NewVaultPKIClient(tlsCfg, logger)
	require.NoError(t, err)

	serverCert, caPEM, err := serverVaultClient.IssueCertificate(ctx, "grpc-server")
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM([]byte(caPEM)))

	// Issue client certificate using the grpc-client role.
	clientTLSCfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: "grpc-client",
		VaultPKITTL:  1 * time.Hour,
	}
	clientVaultClient, err := tlspkg.NewVaultPKIClient(clientTLSCfg, logger)
	require.NoError(t, err)

	clientCert, _, err := clientVaultClient.IssueCertificate(ctx, "grpc-client")
	require.NoError(t, err)

	// Setup OIDC.
	tokenResp := acquireToken(t, testConfig.ClientID, testConfig.ClientSecret)
	require.NotEmpty(t, tokenResp.AccessToken)

	authCfg := config.AuthConfig{
		OIDCEnabled:   true,
		OIDCIssuerURL: fmt.Sprintf("%s/realms/%s", testConfig.KeycloakURL, testConfig.KeycloakRealm),
		OIDCClientID:  testConfig.ClientID,
	}

	provider, err := authoidc.NewProvider(ctx, authCfg, logger)
	require.NoError(t, err)

	// Start server with both mTLS and OIDC.
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(serverTLSConfig)
	mtlsCfg := mtls.Config{}

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			mtls.UnaryInterceptor(mtlsCfg, logger),
			authoidc.UnaryInterceptor(provider, authCfg, logger),
		),
	)

	testService := newIntegrationTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	// Connect with both mTLS and OIDC token.
	// Use ServerName to match the server certificate CN since the cert
	// was issued without IP SANs for 127.0.0.1.
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "grpc-server",
		MinVersion:   tls.VersionTLS12,
	}

	clientCreds := credentials.NewTLS(clientTLSConfig)
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(clientCreds))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	md := metadata.New(map[string]string{
		"authorization": "Bearer " + tokenResp.AccessToken,
	})
	combinedCtx := metadata.NewOutgoingContext(ctx, md)

	resp, err := client.Unary(combinedCtx, &apiv1.UnaryRequest{Message: "combined auth"})
	require.NoError(t, err)
	assert.Equal(t, "combined auth", resp.GetMessage())
}

// newIntegrationTestService creates a test service for integration tests.
func newIntegrationTestService(logger *zap.Logger) apiv1.TestServiceServer {
	return &integrationTestService{logger: logger}
}

// integrationTestService is a simple test service for integration tests.
type integrationTestService struct {
	apiv1.UnimplementedTestServiceServer
	logger *zap.Logger
}

func (s *integrationTestService) Unary(
	_ context.Context,
	req *apiv1.UnaryRequest,
) (*apiv1.UnaryResponse, error) {
	return &apiv1.UnaryResponse{
		Message:   req.GetMessage(),
		Timestamp: time.Now().UnixNano(),
	}, nil
}
