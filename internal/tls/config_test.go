// Package tls_test provides unit tests for the tls config builder.
package tls_test

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/grpc-example/internal/config"
	tlspkg "github.com/vyrodovalexey/grpc-example/internal/tls"
)

func TestBuildServerTLSConfig(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(t *testing.T) config.TLSConfig
		wantErr        bool
		errContains    string
		validateConfig func(t *testing.T, cfg *tls.Config)
	}{
		{
			name: "basic TLS mode",
			setup: func(t *testing.T) config.TLSConfig {
				dir := t.TempDir()
				certPath, keyPath := generateTestCertAndKey(t, dir)
				return config.TLSConfig{
					Mode:       "tls",
					CertPath:   certPath,
					KeyPath:    keyPath,
					ClientAuth: "none",
				}
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Len(t, cfg.Certificates, 1)
				assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
				assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
				assert.Nil(t, cfg.ClientCAs)
			},
		},
		{
			name: "mTLS mode with CA",
			setup: func(t *testing.T) config.TLSConfig {
				dir := t.TempDir()
				certPath, keyPath := generateTestCertAndKey(t, dir)
				caPath := generateTestCA(t, dir)
				return config.TLSConfig{
					Mode:       "mtls",
					CertPath:   certPath,
					KeyPath:    keyPath,
					CAPath:     caPath,
					ClientAuth: "none", // Should be overridden to RequireAndVerifyClientCert
				}
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Len(t, cfg.Certificates, 1)
				assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
				assert.NotNil(t, cfg.ClientCAs)
			},
		},
		{
			name: "mTLS mode with explicit require client auth",
			setup: func(t *testing.T) config.TLSConfig {
				dir := t.TempDir()
				certPath, keyPath := generateTestCertAndKey(t, dir)
				caPath := generateTestCA(t, dir)
				return config.TLSConfig{
					Mode:       "mtls",
					CertPath:   certPath,
					KeyPath:    keyPath,
					CAPath:     caPath,
					ClientAuth: "require",
				}
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
				assert.NotNil(t, cfg.ClientCAs)
			},
		},
		{
			name: "mTLS mode with request client auth",
			setup: func(t *testing.T) config.TLSConfig {
				dir := t.TempDir()
				certPath, keyPath := generateTestCertAndKey(t, dir)
				caPath := generateTestCA(t, dir)
				return config.TLSConfig{
					Mode:       "mtls",
					CertPath:   certPath,
					KeyPath:    keyPath,
					CAPath:     caPath,
					ClientAuth: "request",
				}
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, tls.RequestClientCert, cfg.ClientAuth)
				assert.NotNil(t, cfg.ClientCAs)
			},
		},
		{
			name: "mTLS mode without CA path",
			setup: func(t *testing.T) config.TLSConfig {
				dir := t.TempDir()
				certPath, keyPath := generateTestCertAndKey(t, dir)
				return config.TLSConfig{
					Mode:       "mtls",
					CertPath:   certPath,
					KeyPath:    keyPath,
					CAPath:     "",
					ClientAuth: "none",
				}
			},
			wantErr:     true,
			errContains: "CA certificate path is required for mTLS",
		},
		{
			name: "invalid cert path",
			setup: func(t *testing.T) config.TLSConfig {
				return config.TLSConfig{
					Mode:       "tls",
					CertPath:   "/nonexistent/cert.pem",
					KeyPath:    "/nonexistent/key.pem",
					ClientAuth: "none",
				}
			},
			wantErr:     true,
			errContains: "loading server certificate",
		},
		{
			name: "invalid client auth type",
			setup: func(t *testing.T) config.TLSConfig {
				dir := t.TempDir()
				certPath, keyPath := generateTestCertAndKey(t, dir)
				return config.TLSConfig{
					Mode:       "tls",
					CertPath:   certPath,
					KeyPath:    keyPath,
					ClientAuth: "invalid",
				}
			},
			wantErr:     true,
			errContains: "unsupported client auth type",
		},
		{
			name: "mTLS mode with invalid CA path",
			setup: func(t *testing.T) config.TLSConfig {
				dir := t.TempDir()
				certPath, keyPath := generateTestCertAndKey(t, dir)
				return config.TLSConfig{
					Mode:       "mtls",
					CertPath:   certPath,
					KeyPath:    keyPath,
					CAPath:     "/nonexistent/ca.pem",
					ClientAuth: "none",
				}
			},
			wantErr:     true,
			errContains: "loading CA certificate for mTLS",
		},
		{
			name: "TLS mode with request client auth",
			setup: func(t *testing.T) config.TLSConfig {
				dir := t.TempDir()
				certPath, keyPath := generateTestCertAndKey(t, dir)
				return config.TLSConfig{
					Mode:       "tls",
					CertPath:   certPath,
					KeyPath:    keyPath,
					ClientAuth: "request",
				}
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *tls.Config) {
				assert.Equal(t, tls.RequestClientCert, cfg.ClientAuth)
				assert.Nil(t, cfg.ClientCAs) // No CA pool for non-mTLS mode
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			tlsCfg := tt.setup(t)

			// Act
			result, err := tlspkg.BuildServerTLSConfig(tlsCfg)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.validateConfig != nil {
					tt.validateConfig(t, result)
				}
			}
		})
	}
}
