// Package oidc_test provides unit tests for the oidc provider.
package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
)

func TestNewProvider_DiscoveryFailure(t *testing.T) {
	// Arrange - use a server that returns invalid OIDC discovery
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	// Use a context with immediate cancellation to avoid retries
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	provider, err := oidc.NewProvider(ctx, cfg, logger)

	// Assert
	require.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestNewProvider_ContextCancelledDuringDiscovery(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: "http://unreachable.invalid:1",
		OIDCClientID:  "test-client",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Act
	provider, err := oidc.NewProvider(ctx, cfg, logger)

	// Assert
	require.Error(t, err)
	assert.Nil(t, provider)
}

func TestNewProvider_ValidDiscovery(t *testing.T) {
	// Arrange - create a mock OIDC discovery endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"issuer": "` + "http://" + r.Host + `",
				"authorization_endpoint": "` + "http://" + r.Host + `/auth",
				"token_endpoint": "` + "http://" + r.Host + `/token",
				"jwks_uri": "` + "http://" + r.Host + `/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`))
			return
		}
		if r.URL.Path == "/keys" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	// Act
	provider, err := oidc.NewProvider(context.Background(), cfg, logger)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, provider)
	assert.NotNil(t, provider.Verifier())
}

func TestProvider_Healthy_ReachableProvider(t *testing.T) {
	// Arrange - create a mock OIDC discovery endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"issuer": "` + "http://" + r.Host + `",
				"authorization_endpoint": "` + "http://" + r.Host + `/auth",
				"token_endpoint": "` + "http://" + r.Host + `/token",
				"jwks_uri": "` + "http://" + r.Host + `/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`))
			return
		}
		if r.URL.Path == "/keys" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	provider, err := oidc.NewProvider(context.Background(), cfg, logger)
	require.NoError(t, err)

	// Act
	healthy := provider.Healthy(context.Background())

	// Assert
	assert.True(t, healthy)
}

func TestProvider_Healthy_UnreachableProvider(t *testing.T) {
	// Arrange - create a mock OIDC discovery endpoint, then close it
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"issuer": "` + "http://" + r.Host + `",
				"authorization_endpoint": "` + "http://" + r.Host + `/auth",
				"token_endpoint": "` + "http://" + r.Host + `/token",
				"jwks_uri": "` + "http://" + r.Host + `/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`))
			return
		}
		if r.URL.Path == "/keys" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	provider, err := oidc.NewProvider(context.Background(), cfg, logger)
	require.NoError(t, err)

	// Close the server to simulate provider becoming unavailable
	srv.Close()

	// Act
	healthy := provider.Healthy(context.Background())

	// Assert
	assert.False(t, healthy)
}

func TestProvider_Healthy_RecoveryLogging(t *testing.T) {
	// Arrange - create a mock OIDC discovery endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"issuer": "` + "http://" + r.Host + `",
				"authorization_endpoint": "` + "http://" + r.Host + `/auth",
				"token_endpoint": "` + "http://" + r.Host + `/token",
				"jwks_uri": "` + "http://" + r.Host + `/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`))
			return
		}
		if r.URL.Path == "/keys" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	provider, err := oidc.NewProvider(context.Background(), cfg, logger)
	require.NoError(t, err)

	// First check - should be healthy
	assert.True(t, provider.Healthy(context.Background()))

	// Second check - still healthy (no state change logged)
	assert.True(t, provider.Healthy(context.Background()))
}

func TestProvider_Healthy_RecoveryAfterFailure(t *testing.T) {
	// Arrange - create a controllable mock OIDC discovery endpoint
	var shouldFail atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldFail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"issuer": "` + "http://" + r.Host + `",
				"authorization_endpoint": "` + "http://" + r.Host + `/auth",
				"token_endpoint": "` + "http://" + r.Host + `/token",
				"jwks_uri": "` + "http://" + r.Host + `/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`))
			return
		}
		if r.URL.Path == "/keys" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.AuthConfig{
		OIDCIssuerURL: srv.URL,
		OIDCClientID:  "test-client",
	}

	provider, err := oidc.NewProvider(context.Background(), cfg, logger)
	require.NoError(t, err)

	// Step 1: Provider is healthy initially
	assert.True(t, provider.Healthy(context.Background()))

	// Step 2: Make the server fail - provider becomes unhealthy (wasHealthy=true, isHealthy=false)
	shouldFail.Store(true)
	assert.False(t, provider.Healthy(context.Background()))

	// Step 3: Restore the server - provider recovers (wasHealthy=false, isHealthy=true)
	shouldFail.Store(false)
	assert.True(t, provider.Healthy(context.Background()))
}
