//go:build integration

// Package integration provides integration tests that test with real external services.
// These tests require docker-compose services (Vault, Keycloak) to be running.
package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	vault "github.com/hashicorp/vault/api"
	"go.uber.org/zap"

	authoidc "github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
)

const (
	// integrationTimeout is the default timeout for integration test operations.
	integrationTimeout = 60 * time.Second

	// serviceCheckTimeout is the timeout for checking service availability.
	serviceCheckTimeout = 5 * time.Second
)

// Environment variable names for integration test configuration.
const (
	envVaultAddr     = "VAULT_ADDR"
	envVaultToken    = "VAULT_TOKEN"
	envVaultPKIPath  = "VAULT_PKI_PATH"
	envVaultPKIRole  = "VAULT_PKI_ROLE"
	envKeycloakURL   = "KEYCLOAK_URL"
	envOIDCIssuerURL = "OIDC_ISSUER_URL"
	envKeycloakRealm = "KC_REALM"
	envKeycloakAdmin = "KC_ADMIN_USER"
	envKeycloakPass  = "KC_ADMIN_PASSWORD"
	envClientID      = "KC_CLIENT_ID"
	envClientSecret  = "KC_CLIENT_SECRET"
)

// integrationConfig holds configuration for integration tests.
type integrationConfig struct {
	VaultAddr    string
	VaultToken   string
	VaultPKIPath string
	VaultPKIRole string
	KeycloakURL  string
	// OIDCIssuerURL is the EXPECTED issuer (`iss` claim) value that Keycloak
	// stamps into tokens and reports in its discovery document. Keycloak is
	// configured (KC_HOSTNAME) with a FIXED frontend hostname so this value is
	// identical whether reached from inside docker (`keycloak:8090`) or from
	// the host. Discovery/JWKS are still fetched from KeycloakURL (localhost)
	// via the back-channel; only issuer validation uses this fixed value.
	OIDCIssuerURL string
	KeycloakRealm string
	KeycloakAdmin string
	KeycloakPass  string
	ClientID      string
	ClientSecret  string
}

var testConfig *integrationConfig

// TestMain sets up the integration test configuration.
func TestMain(m *testing.M) {
	testConfig = loadIntegrationConfig()
	os.Exit(m.Run())
}

// loadIntegrationConfig loads configuration from environment variables with defaults.
func loadIntegrationConfig() *integrationConfig {
	return &integrationConfig{
		VaultAddr:     getEnvOrDefault(envVaultAddr, "http://127.0.0.1:8200"),
		VaultToken:    getEnvOrDefault(envVaultToken, "myroot"),
		VaultPKIPath:  getEnvOrDefault(envVaultPKIPath, "pki"),
		VaultPKIRole:  getEnvOrDefault(envVaultPKIRole, "grpc-server"),
		KeycloakURL:   getEnvOrDefault(envKeycloakURL, "http://127.0.0.1:8090"),
		OIDCIssuerURL: getEnvOrDefault(envOIDCIssuerURL, "http://keycloak:8090/realms/grpc-test"),
		KeycloakRealm: getEnvOrDefault(envKeycloakRealm, "grpc-test"),
		KeycloakAdmin: getEnvOrDefault(envKeycloakAdmin, "admin"),
		KeycloakPass:  getEnvOrDefault(envKeycloakPass, "admin"),
		ClientID:      getEnvOrDefault(envClientID, "grpc-server"),
		ClientSecret:  getEnvOrDefault(envClientSecret, "grpc-server-secret"),
	}
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

// newIntegrationContext creates a context with the integration test timeout.
func newIntegrationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), integrationTimeout)
}

// newTestLogger creates a logger for integration tests.
func newTestLogger() *zap.Logger {
	return zap.NewNop()
}

// skipIfVaultUnavailable skips the test if Vault is not reachable.
func skipIfVaultUnavailable(t *testing.T) {
	t.Helper()

	client, err := vault.NewClient(&vault.Config{
		Address: testConfig.VaultAddr,
	})
	if err != nil {
		t.Skipf("skipping: cannot create Vault client: %v", err)
	}
	client.SetToken(testConfig.VaultToken)

	ctx, cancel := context.WithTimeout(context.Background(), serviceCheckTimeout)
	defer cancel()

	health, err := client.Sys().HealthWithContext(ctx)
	if err != nil || health == nil {
		t.Skipf("skipping: Vault is not available at %s: %v", testConfig.VaultAddr, err)
	}
}

// skipIfKeycloakUnavailable skips the test if Keycloak is not reachable.
// Uses the OIDC discovery endpoint as health check since the /health/ready
// endpoint is served on the management port (9000), not the HTTP port.
func skipIfKeycloakUnavailable(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), serviceCheckTimeout)
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

// newOIDCProvider builds an OIDC provider for host-based integration tests.
//
// The server runs inside docker and validates tokens against the FIXED issuer
// (testConfig.OIDCIssuerURL, e.g. http://keycloak:8090/realms/grpc-test). On the
// host that hostname is not resolvable, so discovery and JWKS are fetched from
// the host-reachable KeycloakURL (localhost) while issuer validation still
// enforces the fixed issuer value via InsecureIssuerURLContext.
//
// Issuer validation is NOT disabled: go-oidc continues to require that verified
// tokens carry iss == testConfig.OIDCIssuerURL. This mirrors exactly what the
// docker server enforces, only adapting the discovery transport for the host.
func newOIDCProvider(t *testing.T, ctx context.Context, clientID, audience string, logger *zap.Logger) authoidc.Provider {
	t.Helper()

	discoveryURL := fmt.Sprintf("%s/realms/%s", testConfig.KeycloakURL, testConfig.KeycloakRealm)

	authCfg := config.AuthConfig{
		OIDCEnabled:   true,
		OIDCIssuerURL: discoveryURL,
		OIDCClientID:  clientID,
		OIDCAudience:  audience,
	}

	// Discover at discoveryURL (host-reachable) but pin the expected issuer to
	// the fixed value that tokens actually carry.
	discoveryCtx := gooidc.InsecureIssuerURLContext(ctx, testConfig.OIDCIssuerURL)

	provider, err := authoidc.NewProvider(discoveryCtx, authCfg, logger)
	if err != nil {
		t.Fatalf("failed to create OIDC provider (discovery=%s, issuer=%s): %v",
			discoveryURL, testConfig.OIDCIssuerURL, err)
	}
	return provider
}

// createVaultClient creates a Vault API client for testing.
func createVaultClient(t *testing.T) *vault.Client {
	t.Helper()

	client, err := vault.NewClient(&vault.Config{
		Address: testConfig.VaultAddr,
	})
	if err != nil {
		t.Fatalf("failed to create Vault client: %v", err)
	}
	client.SetToken(testConfig.VaultToken)
	return client
}
