// Package tls_test provides unit tests for Vault PKI metric instrumentation.
package tls_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/config"
	"github.com/vyrodovalexey/grpc-example/internal/metrics"
	tlspkg "github.com/vyrodovalexey/grpc-example/internal/tls"
)

func newVaultPKIClientForMetrics(t *testing.T, handler http.HandlerFunc) (tlspkg.VaultPKIClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	cfg := config.TLSConfig{
		VaultAddr:    srv.URL,
		VaultToken:   "test-token",
		VaultPKIPath: "pki",
		VaultPKIRole: "server",
		VaultPKITTL:  24 * time.Hour,
	}
	client, err := tlspkg.NewVaultPKIClient(cfg, zap.NewNop())
	require.NoError(t, err)
	return client, srv.Close
}

func TestIssueCertificate_RecordsVaultPKIMetric_Success(t *testing.T) {
	// Arrange
	certPEM, keyPEM, caPEM := generatePEMCertAndKey(t)
	client, closeSrv := newVaultPKIClientForMetrics(t, func(w http.ResponseWriter, _ *http.Request) {
		resp := vaultResponse{Data: map[string]any{
			"certificate": certPEM,
			"private_key": keyPEM,
			"issuing_ca":  caPEM,
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer closeSrv()

	counter := metrics.VaultPKIOperationsTotal.WithLabelValues("issue_certificate", metrics.ResultSuccess)
	before := testutil.ToFloat64(counter)

	// Act
	_, _, err := client.IssueCertificate(context.Background(), "test-server")

	// Assert
	require.NoError(t, err)
	assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9,
		"issue_certificate success metric should advance by one")
	assert.Positive(t, testutil.CollectAndCount(metrics.VaultPKIOperationDurationSeconds))
}

func TestIssueCertificate_RecordsVaultPKIMetric_Failure(t *testing.T) {
	// Arrange - empty response triggers the failure path.
	client, closeSrv := newVaultPKIClientForMetrics(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	defer closeSrv()

	counter := metrics.VaultPKIOperationsTotal.WithLabelValues("issue_certificate", metrics.ResultFailure)
	before := testutil.ToFloat64(counter)

	// Act
	_, _, err := client.IssueCertificate(context.Background(), "test-server")

	// Assert
	require.Error(t, err)
	assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9,
		"issue_certificate failure metric should advance by one")
}

func TestGetCACertificate_RecordsVaultPKIMetric_Success(t *testing.T) {
	// Arrange
	_, _, caPEM := generatePEMCertAndKey(t)
	client, closeSrv := newVaultPKIClientForMetrics(t, func(w http.ResponseWriter, _ *http.Request) {
		resp := vaultResponse{Data: map[string]any{"certificate": caPEM}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer closeSrv()

	counter := metrics.VaultPKIOperationsTotal.WithLabelValues("get_ca_certificate", metrics.ResultSuccess)
	before := testutil.ToFloat64(counter)

	// Act
	pool, err := client.GetCACertificate(context.Background())

	// Assert
	require.NoError(t, err)
	require.NotNil(t, pool)
	assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9,
		"get_ca_certificate success metric should advance by one")
}

func TestGetCACertificate_RecordsVaultPKIMetric_Failure(t *testing.T) {
	// Arrange - empty response triggers the failure path.
	client, closeSrv := newVaultPKIClientForMetrics(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	defer closeSrv()

	counter := metrics.VaultPKIOperationsTotal.WithLabelValues("get_ca_certificate", metrics.ResultFailure)
	before := testutil.ToFloat64(counter)

	// Act
	_, err := client.GetCACertificate(context.Background())

	// Assert
	require.Error(t, err)
	assert.InDelta(t, before+1, testutil.ToFloat64(counter), 1e-9,
		"get_ca_certificate failure metric should advance by one")
}
