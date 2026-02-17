//go:build e2e

// Package e2e provides end-to-end tests that test the complete system.
// These tests require the full docker-compose environment to be running.
package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

const (
	// e2eTimeout is the default timeout for e2e test operations.
	e2eTimeout = 120 * time.Second

	// serviceReadyTimeout is the timeout for waiting for services to be ready.
	serviceReadyTimeout = 60 * time.Second

	// serviceCheckInterval is the interval between service readiness checks.
	serviceCheckInterval = 2 * time.Second
)

// e2eConfig holds configuration for e2e tests.
type e2eConfig struct {
	GRPCAddress   string
	VaultAddr     string
	VaultToken    string
	VaultPKIPath  string
	VaultPKIRole  string
	KeycloakURL   string
	KeycloakRealm string
	ClientID      string
	ClientSecret  string
	CertDir       string
}

var testConfig *e2eConfig

// TestMain sets up the e2e test configuration and waits for services.
func TestMain(m *testing.M) {
	testConfig = loadE2EConfig()
	os.Exit(m.Run())
}

// loadE2EConfig loads configuration from environment variables.
func loadE2EConfig() *e2eConfig {
	return &e2eConfig{
		GRPCAddress:   getEnvOrDefault("GRPC_ADDRESS", "127.0.0.1:50051"),
		VaultAddr:     getEnvOrDefault("VAULT_ADDR", "http://127.0.0.1:8200"),
		VaultToken:    getEnvOrDefault("VAULT_TOKEN", "myroot"),
		VaultPKIPath:  getEnvOrDefault("VAULT_PKI_PATH", "pki"),
		VaultPKIRole:  getEnvOrDefault("VAULT_PKI_ROLE", "grpc-server"),
		KeycloakURL:   getEnvOrDefault("KEYCLOAK_URL", "http://127.0.0.1:8090"),
		KeycloakRealm: getEnvOrDefault("KC_REALM", "grpc-test"),
		ClientID:      getEnvOrDefault("KC_CLIENT_ID", "grpc-server"),
		ClientSecret:  getEnvOrDefault("KC_CLIENT_SECRET", "grpc-server-secret"),
		CertDir:       getEnvOrDefault("CERT_DIR", "/tmp/grpc-test-certs"),
	}
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

// newE2EContext creates a context with the e2e test timeout.
func newE2EContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), e2eTimeout)
}

// skipIfServicesUnavailable skips the test if required services are not available.
func skipIfServicesUnavailable(t *testing.T, services ...string) {
	t.Helper()

	for _, svc := range services {
		switch svc {
		case "vault":
			skipIfVaultUnavailable(t)
		case "keycloak":
			skipIfKeycloakUnavailable(t)
		case "grpc-server":
			skipIfGRPCServerUnavailable(t)
		}
	}
}

// skipIfVaultUnavailable skips if Vault is not reachable.
func skipIfVaultUnavailable(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthURL := fmt.Sprintf("%s/v1/sys/health", testConfig.VaultAddr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		t.Skipf("skipping: cannot create Vault health request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("skipping: Vault is not available at %s: %v", testConfig.VaultAddr, err)
	}
	defer resp.Body.Close()
}

// skipIfKeycloakUnavailable skips if Keycloak is not reachable.
// Uses the OIDC discovery endpoint as health check since the /health/ready
// endpoint is served on the management port (9000), not the HTTP port.
func skipIfKeycloakUnavailable(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration",
		testConfig.KeycloakURL, testConfig.KeycloakRealm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		t.Skipf("skipping: cannot create Keycloak discovery request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("skipping: Keycloak is not available at %s: %v", testConfig.KeycloakURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("skipping: Keycloak discovery endpoint returned %d", resp.StatusCode)
	}
}

// skipIfGRPCServerUnavailable skips if the gRPC server is not reachable.
func skipIfGRPCServerUnavailable(t *testing.T) {
	t.Helper()

	// Try to read cert files to determine if the server is set up.
	certDir := testConfig.CertDir
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		t.Skipf("skipping: cert directory %s does not exist", certDir)
	}
}

// acquireKeycloakToken obtains an access token from Keycloak.
func acquireKeycloakToken(t *testing.T) string {
	t.Helper()

	tokenURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/token",
		testConfig.KeycloakURL,
		testConfig.KeycloakRealm,
	)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {testConfig.ClientID},
		"client_secret": {testConfig.ClientSecret},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode, "token request failed: %s", string(body))

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)

	return tokenResp.AccessToken
}

// createMTLSConnection creates a gRPC connection with mTLS using cert files.
func createMTLSConnection(t *testing.T, address, certFile, keyFile, caFile string) (*grpc.ClientConn, apiv1.TestServiceClient) {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	caPEM, err := os.ReadFile(caFile) //nolint:gosec // test file
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)

	client := apiv1.NewTestServiceClient(conn)
	return conn, client
}

// contextWithToken creates a context with a bearer token.
func contextWithToken(ctx context.Context, token string) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + token,
	})
	return metadata.NewOutgoingContext(ctx, md)
}
