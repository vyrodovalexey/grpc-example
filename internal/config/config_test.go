// Package config_test provides unit tests for the config package.
package config_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vyrodovalexey/grpc-example/internal/config"
)

// allEnvVars lists all config-related environment variables.
var allEnvVars = []string{
	"GRPC_PORT", "METRICS_PORT", "LOG_LEVEL", "SHUTDOWN_TIMEOUT",
	"ENABLE_REFLECTION",
	"TLS_ENABLED", "TLS_MODE", "TLS_CERT_PATH", "TLS_KEY_PATH",
	"TLS_CA_PATH", "TLS_CLIENT_AUTH",
	"VAULT_ENABLED", "VAULT_ADDR", "VAULT_TOKEN", "VAULT_TOKEN_FILE",
	"VAULT_PKI_PATH", "VAULT_PKI_ROLE", "VAULT_PKI_TTL",
	"OIDC_ENABLED", "OIDC_ISSUER_URL", "OIDC_CLIENT_ID",
	"OIDC_CLIENT_SECRET", "OIDC_AUDIENCE",
	"AUTH_MODE",
	"OTEL_ENABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_SERVICE_NAME",
}

// clearEnvVars clears all config-related environment variables.
func clearEnvVars(t *testing.T) {
	t.Helper()
	for _, env := range allEnvVars {
		require.NoError(t, os.Unsetenv(env))
	}
}

// setEnvVars sets multiple environment variables and returns a cleanup function.
func setEnvVars(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		require.NoError(t, os.Setenv(k, v))
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cfg *config.Config)
	}{
		{
			name:    "default values when no env vars set",
			envVars: nil,
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, 50051, cfg.GRPCPort)
				assert.Equal(t, 9090, cfg.MetricsPort)
				assert.Equal(t, "info", cfg.LogLevel)
				assert.Equal(t, 30*time.Second, cfg.ShutdownTimeout)
				assert.True(t, cfg.EnableReflection)
				assert.False(t, cfg.TLS.Enabled)
				assert.Equal(t, "none", cfg.TLS.Mode)
				assert.Equal(t, "none", cfg.TLS.ClientAuth)
				assert.Equal(t, 24*time.Hour, cfg.TLS.VaultPKITTL)
				assert.Equal(t, "none", cfg.Auth.Mode)
				assert.False(t, cfg.Auth.OIDCEnabled)
			},
		},
		{
			name: "all env vars set",
			envVars: map[string]string{
				"GRPC_PORT":        "8080",
				"METRICS_PORT":     "9091",
				"LOG_LEVEL":        "debug",
				"SHUTDOWN_TIMEOUT": "60s",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, 8080, cfg.GRPCPort)
				assert.Equal(t, 9091, cfg.MetricsPort)
				assert.Equal(t, "debug", cfg.LogLevel)
				assert.Equal(t, 60*time.Second, cfg.ShutdownTimeout)
			},
		},
		{
			name: "invalid GRPC_PORT - non-numeric",
			envVars: map[string]string{
				"GRPC_PORT": "abc",
			},
			wantErr:     true,
			errContains: "parsing GRPC_PORT",
		},
		{
			name: "invalid GRPC_PORT - negative",
			envVars: map[string]string{
				"GRPC_PORT": "-1",
			},
			wantErr:     true,
			errContains: "invalid gRPC port",
		},
		{
			name: "invalid GRPC_PORT - greater than 65535",
			envVars: map[string]string{
				"GRPC_PORT": "65536",
			},
			wantErr:     true,
			errContains: "invalid gRPC port",
		},
		{
			name: "invalid GRPC_PORT - zero",
			envVars: map[string]string{
				"GRPC_PORT": "0",
			},
			wantErr:     true,
			errContains: "invalid gRPC port",
		},
		{
			name: "invalid METRICS_PORT - non-numeric",
			envVars: map[string]string{
				"METRICS_PORT": "xyz",
			},
			wantErr:     true,
			errContains: "parsing METRICS_PORT",
		},
		{
			name: "invalid METRICS_PORT - negative",
			envVars: map[string]string{
				"METRICS_PORT": "-100",
			},
			wantErr:     true,
			errContains: "invalid metrics port",
		},
		{
			name: "invalid METRICS_PORT - greater than 65535",
			envVars: map[string]string{
				"METRICS_PORT": "70000",
			},
			wantErr:     true,
			errContains: "invalid metrics port",
		},
		{
			name: "invalid LOG_LEVEL",
			envVars: map[string]string{
				"LOG_LEVEL": "invalid",
			},
			wantErr:     true,
			errContains: "invalid log level",
		},
		{
			name: "invalid SHUTDOWN_TIMEOUT - not a duration",
			envVars: map[string]string{
				"SHUTDOWN_TIMEOUT": "invalid",
			},
			wantErr:     true,
			errContains: "parsing SHUTDOWN_TIMEOUT",
		},
		{
			name: "invalid SHUTDOWN_TIMEOUT - negative",
			envVars: map[string]string{
				"SHUTDOWN_TIMEOUT": "-10s",
			},
			wantErr:     true,
			errContains: "invalid shutdown timeout",
		},
		{
			name: "invalid SHUTDOWN_TIMEOUT - zero",
			envVars: map[string]string{
				"SHUTDOWN_TIMEOUT": "0s",
			},
			wantErr:     true,
			errContains: "invalid shutdown timeout",
		},
		{
			name: "port conflict - same ports",
			envVars: map[string]string{
				"GRPC_PORT":    "8080",
				"METRICS_PORT": "8080",
			},
			wantErr:     true,
			errContains: "must be different",
		},
		{
			name: "valid log levels - debug",
			envVars: map[string]string{
				"LOG_LEVEL": "debug",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "debug", cfg.LogLevel)
			},
		},
		{
			name: "valid log levels - warn",
			envVars: map[string]string{
				"LOG_LEVEL": "warn",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "warn", cfg.LogLevel)
			},
		},
		{
			name: "valid log levels - error",
			envVars: map[string]string{
				"LOG_LEVEL": "error",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "error", cfg.LogLevel)
			},
		},
		{
			name: "boundary port values - min valid",
			envVars: map[string]string{
				"GRPC_PORT":    "1",
				"METRICS_PORT": "2",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, 1, cfg.GRPCPort)
				assert.Equal(t, 2, cfg.MetricsPort)
			},
		},
		{
			name: "reflection disabled via env",
			envVars: map[string]string{
				"ENABLE_REFLECTION": "false",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.False(t, cfg.EnableReflection)
			},
		},
		{
			name: "reflection enabled via env",
			envVars: map[string]string{
				"ENABLE_REFLECTION": "true",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.EnableReflection)
			},
		},
		{
			name: "invalid ENABLE_REFLECTION value",
			envVars: map[string]string{
				"ENABLE_REFLECTION": "notabool",
			},
			wantErr:     true,
			errContains: "parsing ENABLE_REFLECTION",
		},
		{
			name: "boundary port values - max valid",
			envVars: map[string]string{
				"GRPC_PORT":    "65535",
				"METRICS_PORT": "65534",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, 65535, cfg.GRPCPort)
				assert.Equal(t, 65534, cfg.MetricsPort)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			clearEnvVars(t)
			if tt.envVars != nil {
				setEnvVars(t, tt.envVars)
			}
			t.Cleanup(func() { clearEnvVars(t) })

			// Act
			cfg, err := config.Load()

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, cfg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

func TestLoad_TLSConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "TLS enabled with cert and key",
			envVars: map[string]string{
				"TLS_ENABLED":   "true",
				"TLS_MODE":      "tls",
				"TLS_CERT_PATH": "/path/to/cert.pem",
				"TLS_KEY_PATH":  "/path/to/key.pem",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.TLS.Enabled)
				assert.Equal(t, "tls", cfg.TLS.Mode)
				assert.Equal(t, "/path/to/cert.pem", cfg.TLS.CertPath)
				assert.Equal(t, "/path/to/key.pem", cfg.TLS.KeyPath)
			},
		},
		{
			name: "TLS enabled mTLS mode with CA",
			envVars: map[string]string{
				"TLS_ENABLED":   "true",
				"TLS_MODE":      "mtls",
				"TLS_CERT_PATH": "/path/to/cert.pem",
				"TLS_KEY_PATH":  "/path/to/key.pem",
				"TLS_CA_PATH":   "/path/to/ca.pem",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.TLS.Enabled)
				assert.Equal(t, "mtls", cfg.TLS.Mode)
				assert.Equal(t, "/path/to/ca.pem", cfg.TLS.CAPath)
			},
		},
		{
			name: "TLS enabled with client auth",
			envVars: map[string]string{
				"TLS_ENABLED":     "true",
				"TLS_MODE":        "tls",
				"TLS_CERT_PATH":   "/path/to/cert.pem",
				"TLS_KEY_PATH":    "/path/to/key.pem",
				"TLS_CLIENT_AUTH": "request",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "request", cfg.TLS.ClientAuth)
			},
		},
		{
			name: "TLS enabled - missing cert path",
			envVars: map[string]string{
				"TLS_ENABLED":  "true",
				"TLS_MODE":     "tls",
				"TLS_KEY_PATH": "/path/to/key.pem",
			},
			wantErr:     true,
			errContains: "TLS certificate path is required",
		},
		{
			name: "TLS enabled - missing key path",
			envVars: map[string]string{
				"TLS_ENABLED":   "true",
				"TLS_MODE":      "tls",
				"TLS_CERT_PATH": "/path/to/cert.pem",
			},
			wantErr:     true,
			errContains: "TLS key path is required",
		},
		{
			name: "mTLS mode - missing CA path",
			envVars: map[string]string{
				"TLS_ENABLED":   "true",
				"TLS_MODE":      "mtls",
				"TLS_CERT_PATH": "/path/to/cert.pem",
				"TLS_KEY_PATH":  "/path/to/key.pem",
			},
			wantErr:     true,
			errContains: "TLS CA path is required",
		},
		{
			name: "invalid TLS_ENABLED value",
			envVars: map[string]string{
				"TLS_ENABLED": "notabool",
			},
			wantErr:     true,
			errContains: "parsing TLS_ENABLED",
		},
		{
			name: "invalid TLS mode",
			envVars: map[string]string{
				"TLS_ENABLED":   "true",
				"TLS_MODE":      "invalid",
				"TLS_CERT_PATH": "/path/to/cert.pem",
				"TLS_KEY_PATH":  "/path/to/key.pem",
			},
			wantErr:     true,
			errContains: "invalid TLS mode",
		},
		{
			name: "invalid client auth mode",
			envVars: map[string]string{
				"TLS_ENABLED":     "true",
				"TLS_MODE":        "tls",
				"TLS_CERT_PATH":   "/path/to/cert.pem",
				"TLS_KEY_PATH":    "/path/to/key.pem",
				"TLS_CLIENT_AUTH": "invalid",
			},
			wantErr:     true,
			errContains: "invalid client auth",
		},
		{
			name: "TLS disabled - no validation of cert paths",
			envVars: map[string]string{
				"TLS_ENABLED": "false",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.False(t, cfg.TLS.Enabled)
			},
		},
		{
			name: "TLS enabled with Vault - cert path not required",
			envVars: map[string]string{
				"TLS_ENABLED":   "true",
				"TLS_MODE":      "tls",
				"VAULT_ENABLED": "true",
				"VAULT_ADDR":    "http://vault:8200",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.TLS.Enabled)
				assert.True(t, cfg.TLS.VaultEnabled)
			},
		},
		{
			name: "mTLS with Vault - CA path not required",
			envVars: map[string]string{
				"TLS_ENABLED":   "true",
				"TLS_MODE":      "mtls",
				"VAULT_ENABLED": "true",
				"VAULT_ADDR":    "http://vault:8200",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.TLS.Enabled)
				assert.Equal(t, "mtls", cfg.TLS.Mode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			clearEnvVars(t)
			setEnvVars(t, tt.envVars)
			t.Cleanup(func() { clearEnvVars(t) })

			// Act
			cfg, err := config.Load()

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

func TestLoad_VaultConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "vault config loaded from env",
			envVars: map[string]string{
				"VAULT_ENABLED":  "true",
				"VAULT_ADDR":     "http://vault:8200",
				"VAULT_TOKEN":    "s.test-token",
				"VAULT_PKI_PATH": "pki/intermediate",
				"VAULT_PKI_ROLE": "grpc-server",
				"VAULT_PKI_TTL":  "48h",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.TLS.VaultEnabled)
				assert.Equal(t, "http://vault:8200", cfg.TLS.VaultAddr)
				assert.Equal(t, "s.test-token", cfg.TLS.VaultToken)
				assert.Equal(t, "pki/intermediate", cfg.TLS.VaultPKIPath)
				assert.Equal(t, "grpc-server", cfg.TLS.VaultPKIRole)
				assert.Equal(t, 48*time.Hour, cfg.TLS.VaultPKITTL)
			},
		},
		{
			name: "invalid VAULT_ENABLED value",
			envVars: map[string]string{
				"VAULT_ENABLED": "notabool",
			},
			wantErr:     true,
			errContains: "parsing VAULT_ENABLED",
		},
		{
			name: "invalid VAULT_PKI_TTL value",
			envVars: map[string]string{
				"VAULT_PKI_TTL": "invalid",
			},
			wantErr:     true,
			errContains: "parsing VAULT_PKI_TTL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			clearEnvVars(t)
			setEnvVars(t, tt.envVars)
			t.Cleanup(func() { clearEnvVars(t) })

			// Act
			cfg, err := config.Load()

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

func TestLoad_VaultTokenFile(t *testing.T) {
	t.Run("reads token from file", func(t *testing.T) {
		// Arrange
		clearEnvVars(t)
		t.Cleanup(func() { clearEnvVars(t) })

		tokenFile := t.TempDir() + "/vault-token"
		require.NoError(t, os.WriteFile(tokenFile, []byte("s.file-token\n"), 0o600))

		setEnvVars(t, map[string]string{
			"VAULT_ENABLED":    "true",
			"VAULT_TOKEN_FILE": tokenFile,
		})

		// Act
		cfg, err := config.Load()

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "s.file-token", cfg.TLS.VaultToken)
	})

	t.Run("env token takes precedence over file", func(t *testing.T) {
		// Arrange
		clearEnvVars(t)
		t.Cleanup(func() { clearEnvVars(t) })

		tokenFile := t.TempDir() + "/vault-token"
		require.NoError(t, os.WriteFile(tokenFile, []byte("s.file-token"), 0o600))

		setEnvVars(t, map[string]string{
			"VAULT_ENABLED":    "true",
			"VAULT_TOKEN":      "s.env-token",
			"VAULT_TOKEN_FILE": tokenFile,
		})

		// Act
		cfg, err := config.Load()

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "s.env-token", cfg.TLS.VaultToken)
	})

	t.Run("error on nonexistent token file", func(t *testing.T) {
		// Arrange
		clearEnvVars(t)
		t.Cleanup(func() { clearEnvVars(t) })

		setEnvVars(t, map[string]string{
			"VAULT_TOKEN_FILE": "/nonexistent/path/token",
		})

		// Act
		_, err := config.Load()

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading vault token file")
	})
}

func TestLoad_OIDCConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "OIDC config loaded from env",
			envVars: map[string]string{
				"OIDC_ENABLED":       "true",
				"OIDC_ISSUER_URL":    "https://issuer.example.com",
				"OIDC_CLIENT_ID":     "test-client",
				"OIDC_CLIENT_SECRET": "secret123",
				"OIDC_AUDIENCE":      "api.example.com",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.Auth.OIDCEnabled)
				assert.Equal(t, "https://issuer.example.com", cfg.Auth.OIDCIssuerURL)
				assert.Equal(t, "test-client", cfg.Auth.OIDCClientID)
				assert.Equal(t, "secret123", cfg.Auth.OIDCClientSecret)
				assert.Equal(t, "api.example.com", cfg.Auth.OIDCAudience)
			},
		},
		{
			name: "OIDC enabled - missing issuer URL",
			envVars: map[string]string{
				"OIDC_ENABLED":   "true",
				"OIDC_CLIENT_ID": "test-client",
			},
			wantErr:     true,
			errContains: "OIDC issuer URL is required",
		},
		{
			name: "OIDC enabled - missing client ID",
			envVars: map[string]string{
				"OIDC_ENABLED":    "true",
				"OIDC_ISSUER_URL": "https://issuer.example.com",
			},
			wantErr:     true,
			errContains: "OIDC client ID is required",
		},
		{
			name: "invalid OIDC_ENABLED value",
			envVars: map[string]string{
				"OIDC_ENABLED": "notabool",
			},
			wantErr:     true,
			errContains: "parsing OIDC_ENABLED",
		},
		{
			name: "OIDC disabled - no validation",
			envVars: map[string]string{
				"OIDC_ENABLED": "false",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.False(t, cfg.Auth.OIDCEnabled)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			clearEnvVars(t)
			setEnvVars(t, tt.envVars)
			t.Cleanup(func() { clearEnvVars(t) })

			// Act
			cfg, err := config.Load()

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

func TestLoad_AuthModeConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "auth mode none",
			envVars: map[string]string{
				"AUTH_MODE": "none",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "none", cfg.Auth.Mode)
			},
		},
		{
			name: "auth mode mtls",
			envVars: map[string]string{
				"AUTH_MODE": "mtls",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "mtls", cfg.Auth.Mode)
			},
		},
		{
			name: "auth mode oidc",
			envVars: map[string]string{
				"AUTH_MODE": "oidc",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "oidc", cfg.Auth.Mode)
			},
		},
		{
			name: "auth mode both",
			envVars: map[string]string{
				"AUTH_MODE": "both",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "both", cfg.Auth.Mode)
			},
		},
		{
			name: "invalid auth mode",
			envVars: map[string]string{
				"AUTH_MODE": "invalid",
			},
			wantErr:     true,
			errContains: "invalid auth mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			clearEnvVars(t)
			setEnvVars(t, tt.envVars)
			t.Cleanup(func() { clearEnvVars(t) })

			// Act
			cfg, err := config.Load()

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

func TestConfig_String(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		contains    []string
		notContains []string
	}{
		{
			name: "basic config - TLS disabled",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth: config.AuthConfig{
					Mode: "none",
				},
			},
			contains: []string{
				"GRPCPort: 50051",
				"MetricsPort: 9090",
				"LogLevel: info",
				"ShutdownTimeout: 30s",
				"TLS: disabled",
				"AuthMode: none",
			},
		},
		{
			name: "TLS enabled config",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled: true,
					Mode:    "tls",
				},
				Auth: config.AuthConfig{
					Mode: "none",
				},
			},
			contains: []string{
				"TLS: enabled",
				"TLSMode: tls",
			},
			notContains: []string{
				"TLS: disabled",
			},
		},
		{
			name: "TLS enabled with Vault - sensitive values masked",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:      true,
					Mode:         "mtls",
					VaultEnabled: true,
					VaultAddr:    "http://vault:8200",
					VaultToken:   "s.super-secret-token",
				},
				Auth: config.AuthConfig{
					Mode: "none",
				},
			},
			contains: []string{
				"TLS: enabled",
				"TLSMode: mtls",
				"VaultAddr: ****",
				"VaultToken: ****",
			},
			notContains: []string{
				"s.super-secret-token",
				"http://vault:8200",
			},
		},
		{
			name: "OIDC enabled - all sensitive values masked",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth: config.AuthConfig{
					Mode:             "oidc",
					OIDCEnabled:      true,
					OIDCIssuerURL:    "https://issuer.example.com",
					OIDCClientID:     "my-client-id",
					OIDCClientSecret: "super-secret",
				},
			},
			contains: []string{
				"AuthMode: oidc",
				"OIDC: enabled",
				"OIDCIssuer: ****",
				"OIDCClientID: ****",
				"OIDCClientSecret: ****",
			},
			notContains: []string{
				"super-secret",
				"https://issuer.example.com",
				"my-client-id",
			},
		},
		{
			name: "string representation with custom values",
			config: &config.Config{
				GRPCPort:        8080,
				MetricsPort:     9091,
				LogLevel:        "debug",
				ShutdownTimeout: 60 * time.Second,
				Auth: config.AuthConfig{
					Mode: "none",
				},
			},
			contains: []string{
				"GRPCPort: 8080",
				"MetricsPort: 9091",
				"LogLevel: debug",
				"ShutdownTimeout: 1m0s",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result := tt.config.String()

			// Assert
			for _, substr := range tt.contains {
				assert.Contains(t, result, substr)
			}
			for _, substr := range tt.notContains {
				assert.NotContains(t, result, substr)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr error
	}{
		{
			name: "valid config",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth:            config.AuthConfig{Mode: "none"},
			},
			wantErr: nil,
		},
		{
			name: "invalid gRPC port - too low",
			config: &config.Config{
				GRPCPort:        0,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: config.ErrInvalidGRPCPort,
		},
		{
			name: "invalid gRPC port - too high",
			config: &config.Config{
				GRPCPort:        65536,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: config.ErrInvalidGRPCPort,
		},
		{
			name: "invalid metrics port - too low",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     0,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: config.ErrInvalidMetricsPort,
		},
		{
			name: "invalid metrics port - too high",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     65536,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: config.ErrInvalidMetricsPort,
		},
		{
			name: "port conflict",
			config: &config.Config{
				GRPCPort:        8080,
				MetricsPort:     8080,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: config.ErrPortConflict,
		},
		{
			name: "invalid log level",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "invalid",
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: config.ErrInvalidLogLevel,
		},
		{
			name: "invalid shutdown timeout - zero",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 0,
			},
			wantErr: config.ErrInvalidShutdownTimeout,
		},
		{
			name: "invalid shutdown timeout - negative",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: -1 * time.Second,
			},
			wantErr: config.ErrInvalidShutdownTimeout,
		},
		{
			name: "valid TLS config",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "tls",
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "/path/to/key.pem",
					ClientAuth: "none",
				},
				Auth: config.AuthConfig{Mode: "none"},
			},
			wantErr: nil,
		},
		{
			name: "invalid TLS mode",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "invalid",
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "/path/to/key.pem",
					ClientAuth: "none",
				},
			},
			wantErr: config.ErrInvalidTLSMode,
		},
		{
			name: "invalid client auth",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "tls",
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "/path/to/key.pem",
					ClientAuth: "invalid",
				},
			},
			wantErr: config.ErrInvalidClientAuth,
		},
		{
			name: "TLS enabled - missing cert path",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "tls",
					CertPath:   "",
					KeyPath:    "/path/to/key.pem",
					ClientAuth: "none",
				},
			},
			wantErr: config.ErrTLSCertRequired,
		},
		{
			name: "TLS enabled - missing key path",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "tls",
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "",
					ClientAuth: "none",
				},
			},
			wantErr: config.ErrTLSKeyRequired,
		},
		{
			name: "mTLS mode - missing CA path",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "mtls",
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "/path/to/key.pem",
					CAPath:     "",
					ClientAuth: "none",
				},
			},
			wantErr: config.ErrTLSCARequired,
		},
		{
			name: "TLS enabled with Vault - cert path not required",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:      true,
					Mode:         "tls",
					VaultEnabled: true,
					ClientAuth:   "none",
				},
				Auth: config.AuthConfig{Mode: "none"},
			},
			wantErr: nil,
		},
		{
			name: "invalid auth mode",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth: config.AuthConfig{
					Mode: "invalid",
				},
			},
			wantErr: config.ErrInvalidAuthMode,
		},
		{
			name: "OIDC enabled - missing issuer",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth: config.AuthConfig{
					Mode:         "oidc",
					OIDCEnabled:  true,
					OIDCClientID: "test",
				},
			},
			wantErr: config.ErrOIDCIssuerRequired,
		},
		{
			name: "OIDC enabled - missing client ID",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth: config.AuthConfig{
					Mode:          "oidc",
					OIDCEnabled:   true,
					OIDCIssuerURL: "https://issuer.example.com",
				},
			},
			wantErr: config.ErrOIDCClientIDRequired,
		},
		{
			name: "valid OIDC config",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth: config.AuthConfig{
					Mode:          "oidc",
					OIDCEnabled:   true,
					OIDCIssuerURL: "https://issuer.example.com",
					OIDCClientID:  "test-client",
				},
			},
			wantErr: nil,
		},
		{
			name: "TLS disabled - empty mode and client auth treated as defaults",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled: false,
				},
				Auth: config.AuthConfig{Mode: "none"},
			},
			wantErr: nil,
		},
		{
			name: "TLS enabled - empty mode is invalid without applyDefaults",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "",
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "/path/to/key.pem",
					ClientAuth: "none",
				},
			},
			wantErr: config.ErrInvalidTLSMode,
		},
		{
			name: "TLS enabled - empty client auth is invalid without applyDefaults",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "tls",
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "/path/to/key.pem",
					ClientAuth: "",
				},
			},
			wantErr: config.ErrInvalidClientAuth,
		},
		{
			name: "empty auth mode is invalid without applyDefaults",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth: config.AuthConfig{
					Mode: "",
				},
			},
			wantErr: config.ErrInvalidAuthMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			err := tt.config.Validate()

			// Assert
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_GRPCAddress(t *testing.T) {
	tests := []struct {
		name     string
		grpcPort int
		want     string
	}{
		{
			name:     "default port",
			grpcPort: 50051,
			want:     ":50051",
		},
		{
			name:     "custom port",
			grpcPort: 8080,
			want:     ":8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			cfg := &config.Config{GRPCPort: tt.grpcPort}

			// Act
			result := cfg.GRPCAddress()

			// Assert
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestValidLogLevels(t *testing.T) {
	validLevels := []string{"debug", "info", "warn", "error"}

	for _, level := range validLevels {
		t.Run("valid_"+level, func(t *testing.T) {
			// Arrange
			clearEnvVars(t)
			setEnvVars(t, map[string]string{"LOG_LEVEL": level})
			t.Cleanup(func() { clearEnvVars(t) })

			// Act
			cfg, err := config.Load()

			// Assert
			require.NoError(t, err)
			assert.Equal(t, level, cfg.LogLevel)
		})
	}
}

func TestInvalidLogLevels(t *testing.T) {
	invalidLevels := []string{"DEBUG", "INFO", "WARN", "ERROR", "trace", "fatal", ""}

	for _, level := range invalidLevels {
		testName := level
		if level == "" {
			testName = "empty"
		}
		t.Run("invalid_"+testName, func(t *testing.T) {
			// Arrange
			cfg := &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        level,
				ShutdownTimeout: 30 * time.Second,
			}

			// Act
			err := cfg.Validate()

			// Assert
			require.Error(t, err)
			assert.ErrorIs(t, err, config.ErrInvalidLogLevel)
		})
	}
}

func TestShutdownTimeoutParsing(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     time.Duration
	}{
		{
			name:     "seconds",
			envValue: "10s",
			want:     10 * time.Second,
		},
		{
			name:     "minutes",
			envValue: "2m",
			want:     2 * time.Minute,
		},
		{
			name:     "mixed duration",
			envValue: "1m30s",
			want:     90 * time.Second,
		},
		{
			name:     "milliseconds",
			envValue: "500ms",
			want:     500 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			clearEnvVars(t)
			setEnvVars(t, map[string]string{"SHUTDOWN_TIMEOUT": tt.envValue})
			t.Cleanup(func() { clearEnvVars(t) })

			// Act
			cfg, err := config.Load()

			// Assert
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.ShutdownTimeout)
		})
	}
}

func TestConfigStringFormat(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		GRPCPort:        50051,
		MetricsPort:     9090,
		LogLevel:        "info",
		ShutdownTimeout: 30 * time.Second,
	}

	// Act
	result := cfg.String()

	// Assert
	assert.True(t, strings.HasPrefix(result, "Config{"))
	assert.True(t, strings.HasSuffix(result, "}"))
}

func TestValidTLSModes(t *testing.T) {
	validModes := []string{"none", "tls", "mtls"}

	for _, mode := range validModes {
		t.Run("valid_tls_mode_"+mode, func(t *testing.T) {
			// Arrange
			cfg := &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       mode,
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "/path/to/key.pem",
					CAPath:     "/path/to/ca.pem",
					ClientAuth: "none",
				},
				Auth: config.AuthConfig{Mode: "none"},
			}

			// Act
			err := cfg.Validate()

			// Assert
			require.NoError(t, err)
		})
	}
}

func TestValidClientAuthModes(t *testing.T) {
	validModes := []string{"none", "request", "require"}

	for _, mode := range validModes {
		t.Run("valid_client_auth_"+mode, func(t *testing.T) {
			// Arrange
			cfg := &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				TLS: config.TLSConfig{
					Enabled:    true,
					Mode:       "tls",
					CertPath:   "/path/to/cert.pem",
					KeyPath:    "/path/to/key.pem",
					ClientAuth: mode,
				},
				Auth: config.AuthConfig{Mode: "none"},
			}

			// Act
			err := cfg.Validate()

			// Assert
			require.NoError(t, err)
		})
	}
}

func TestValidAuthModes(t *testing.T) {
	validModes := []string{"none", "mtls", "oidc", "both"}

	for _, mode := range validModes {
		t.Run("valid_auth_mode_"+mode, func(t *testing.T) {
			// Arrange
			cfg := &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
				Auth: config.AuthConfig{
					Mode: mode,
				},
			}

			// Act
			err := cfg.Validate()

			// Assert
			require.NoError(t, err)
		})
	}
}

func TestLoad_OTELConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "OTEL_ENABLED=true sets cfg.OTEL.Enabled",
			envVars: map[string]string{
				"OTEL_ENABLED": "true",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.OTEL.Enabled)
			},
		},
		{
			name: "OTEL_ENABLED=false sets cfg.OTEL.Enabled to false",
			envVars: map[string]string{
				"OTEL_ENABLED": "false",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.False(t, cfg.OTEL.Enabled)
			},
		},
		{
			name: "OTEL_EXPORTER_OTLP_ENDPOINT sets endpoint",
			envVars: map[string]string{
				"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:4318",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "localhost:4318", cfg.OTEL.Endpoint)
			},
		},
		{
			name: "OTEL_SERVICE_NAME sets service name",
			envVars: map[string]string{
				"OTEL_SERVICE_NAME": "my-service",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "my-service", cfg.OTEL.ServiceName)
			},
		},
		{
			name: "OTEL_ENABLED=invalid returns parse error",
			envVars: map[string]string{
				"OTEL_ENABLED": "invalid",
			},
			wantErr:     true,
			errContains: "parsing OTEL_ENABLED",
		},
		{
			name: "all OTEL env vars set",
			envVars: map[string]string{
				"OTEL_ENABLED":                "true",
				"OTEL_EXPORTER_OTLP_ENDPOINT": "collector.example.com:4318",
				"OTEL_SERVICE_NAME":           "my-grpc-service",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.OTEL.Enabled)
				assert.Equal(t, "collector.example.com:4318", cfg.OTEL.Endpoint)
				assert.Equal(t, "my-grpc-service", cfg.OTEL.ServiceName)
			},
		},
		{
			name:    "OTEL defaults when no env vars set",
			envVars: map[string]string{},
			wantErr: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.False(t, cfg.OTEL.Enabled)
				assert.Empty(t, cfg.OTEL.Endpoint)
				assert.Empty(t, cfg.OTEL.ServiceName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			clearEnvVars(t)
			if len(tt.envVars) > 0 {
				setEnvVars(t, tt.envVars)
			}
			t.Cleanup(func() { clearEnvVars(t) })

			// Act
			cfg, err := config.Load()

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

func TestConfig_String_OTELEnabled(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		GRPCPort:        50051,
		MetricsPort:     9090,
		LogLevel:        "info",
		ShutdownTimeout: 30 * time.Second,
		Auth: config.AuthConfig{
			Mode: "none",
		},
		OTEL: config.OTELConfig{
			Enabled:     true,
			Endpoint:    "localhost:4318",
			ServiceName: "test-service",
		},
	}

	// Act
	result := cfg.String()

	// Assert
	assert.Contains(t, result, "OTEL: enabled")
	assert.Contains(t, result, "OTELEndpoint: localhost:4318")
	assert.Contains(t, result, "OTELServiceName: test-service")
}

func TestConfig_String_OTELDisabled(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		GRPCPort:        50051,
		MetricsPort:     9090,
		LogLevel:        "info",
		ShutdownTimeout: 30 * time.Second,
		Auth: config.AuthConfig{
			Mode: "none",
		},
		OTEL: config.OTELConfig{
			Enabled: false,
		},
	}

	// Act
	result := cfg.String()

	// Assert
	assert.NotContains(t, result, "OTEL: enabled")
	assert.NotContains(t, result, "OTELEndpoint")
}
