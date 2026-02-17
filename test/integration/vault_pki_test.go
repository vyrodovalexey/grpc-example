//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/grpc-example/internal/config"
	tlspkg "github.com/vyrodovalexey/grpc-example/internal/tls"
)

func TestIntegration_VaultPKI_IssueCertificate(t *testing.T) {
	skipIfVaultUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	cfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, newTestLogger())
	require.NoError(t, err)

	cert, caPEM, err := client.IssueCertificate(ctx, "localhost")
	require.NoError(t, err)

	// Verify certificate was issued.
	assert.NotEmpty(t, cert.Certificate, "certificate should not be empty")
	assert.NotNil(t, cert.PrivateKey, "private key should not be nil")
	assert.NotEmpty(t, caPEM, "CA PEM should not be empty")
}

func TestIntegration_VaultPKI_IssueCertificateWithDifferentCN(t *testing.T) {
	skipIfVaultUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	cfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, newTestLogger())
	require.NoError(t, err)

	commonNames := []string{"grpc-server", "localhost"}

	for _, cn := range commonNames {
		t.Run(cn, func(t *testing.T) {
			cert, _, err := client.IssueCertificate(ctx, cn)
			require.NoError(t, err)
			assert.NotEmpty(t, cert.Certificate)
		})
	}
}

func TestIntegration_VaultPKI_CertificateRenewal(t *testing.T) {
	skipIfVaultUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	cfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, newTestLogger())
	require.NoError(t, err)

	// Issue first certificate.
	cert1, _, err := client.IssueCertificate(ctx, "localhost")
	require.NoError(t, err)

	// Issue second certificate (simulating renewal).
	cert2, _, err := client.IssueCertificate(ctx, "localhost")
	require.NoError(t, err)

	// Both should be valid but different certificates.
	assert.NotEmpty(t, cert1.Certificate)
	assert.NotEmpty(t, cert2.Certificate)

	// The raw certificate bytes should differ (different serial numbers).
	assert.NotEqual(t, cert1.Certificate[0], cert2.Certificate[0],
		"renewed certificate should have different serial number")
}

func TestIntegration_VaultPKI_GetCACertificate(t *testing.T) {
	skipIfVaultUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	cfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, newTestLogger())
	require.NoError(t, err)

	caPool, err := client.GetCACertificate(ctx)
	require.NoError(t, err)
	assert.NotNil(t, caPool, "CA cert pool should not be nil")
}

func TestIntegration_VaultPKI_InvalidToken(t *testing.T) {
	skipIfVaultUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	cfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   "invalid-token",
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, newTestLogger())
	require.NoError(t, err)

	_, _, err = client.IssueCertificate(ctx, "should-fail")
	require.Error(t, err)
}

func TestIntegration_VaultPKI_InvalidPKIPath(t *testing.T) {
	skipIfVaultUnavailable(t)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	cfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: "nonexistent-pki",
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, newTestLogger())
	require.NoError(t, err)

	_, _, err = client.IssueCertificate(ctx, "should-fail")
	require.Error(t, err)
}

func TestIntegration_VaultPKI_ContextCancellation(t *testing.T) {
	skipIfVaultUnavailable(t)

	ctx, cancel := newIntegrationContext()
	// Cancel immediately.
	cancel()

	cfg := config.TLSConfig{
		VaultEnabled: true,
		VaultAddr:    testConfig.VaultAddr,
		VaultToken:   testConfig.VaultToken,
		VaultPKIPath: testConfig.VaultPKIPath,
		VaultPKIRole: testConfig.VaultPKIRole,
		VaultPKITTL:  1 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, newTestLogger())
	require.NoError(t, err)

	_, _, err = client.IssueCertificate(ctx, "should-fail")
	require.Error(t, err)
}
