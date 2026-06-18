// Package oidc_test provides unit tests for OIDC provider metric instrumentation.
package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
	"github.com/vyrodovalexey/grpc-example/internal/metrics"
)

// newDiscoveryServer returns an httptest server that serves a minimal but valid
// OIDC discovery document plus an empty JWKS, suitable for constructing a real
// provider whose verifier can be exercised.
func newDiscoveryServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"issuer": "` + "http://" + r.Host + `",
				"authorization_endpoint": "` + "http://" + r.Host + `/auth",
				"token_endpoint": "` + "http://" + r.Host + `/token",
				"jwks_uri": "` + "http://" + r.Host + `/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`))
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestMeteredVerifier_RecordsFailure verifies that the verifier returned by a real
// provider records an OIDC verification metric on the failure path. A malformed
// token cannot be verified (empty JWKS), so the failure counter must advance.
func TestMeteredVerifier_RecordsFailure(t *testing.T) {
	// Arrange
	srv := newDiscoveryServer()
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	provider, err := oidc.NewProvider(context.Background(), cfg, logger)
	require.NoError(t, err)

	verifier := provider.Verifier()
	require.NotNil(t, verifier)

	failureCounter := metrics.OIDCVerificationTotal.WithLabelValues(metrics.ResultFailure)
	before := testutil.ToFloat64(failureCounter)

	// Act - verifying a non-JWT token must fail and be recorded as a failure.
	token, verifyErr := verifier.Verify(context.Background(), "not-a-valid-jwt")

	// Assert
	require.Error(t, verifyErr)
	assert.Nil(t, token)
	assert.InDelta(t, before+1, testutil.ToFloat64(failureCounter), 1e-9,
		"OIDC verification failure metric should advance by one")
}

// TestProvider_DiscoveryRecordsProviderRequestMetric verifies that successful
// discovery during provider construction advances the discovery request counter.
func TestProvider_DiscoveryRecordsProviderRequestMetric(t *testing.T) {
	// Arrange
	srv := newDiscoveryServer()
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	successCounter := metrics.OIDCProviderRequestsTotal.WithLabelValues("discovery", metrics.ResultSuccess)
	before := testutil.ToFloat64(successCounter)

	// Act
	provider, err := oidc.NewProvider(context.Background(), cfg, logger)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, provider)
	assert.InDelta(t, before+1, testutil.ToFloat64(successCounter), 1e-9,
		"discovery success metric should advance by one")
}

// TestProvider_HealthCheckRecordsProviderRequestMetric verifies that the health
// check path records the OIDC provider request metric for both healthy and
// unhealthy outcomes.
func TestProvider_HealthCheckRecordsProviderRequestMetric(t *testing.T) {
	// Arrange
	srv := newDiscoveryServer()
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	provider, err := oidc.NewProvider(context.Background(), cfg, logger)
	require.NoError(t, err)

	healthyCounter := metrics.OIDCProviderRequestsTotal.WithLabelValues("health_check", metrics.ResultSuccess)
	healthyBefore := testutil.ToFloat64(healthyCounter)

	// Act - a reachable provider records a successful health_check request.
	assert.True(t, provider.Healthy(context.Background()))

	// Assert
	assert.InDelta(t, healthyBefore+1, testutil.ToFloat64(healthyCounter), 1e-9,
		"successful health_check metric should advance by one")

	// Arrange - take the provider offline to exercise the failure path.
	failureCounter := metrics.OIDCProviderRequestsTotal.WithLabelValues("health_check", metrics.ResultFailure)
	failureBefore := testutil.ToFloat64(failureCounter)
	srv.Close()

	// Act
	assert.False(t, provider.Healthy(context.Background()))

	// Assert
	assert.InDelta(t, failureBefore+1, testutil.ToFloat64(failureCounter), 1e-9,
		"failed health_check metric should advance by one")
}
