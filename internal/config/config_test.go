// Package config_test provides unit tests for the config package.
package config_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alexey/grpc-example/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearEnvVars clears all config-related environment variables.
func clearEnvVars(t *testing.T) {
	t.Helper()
	envVars := []string{"GRPC_PORT", "METRICS_PORT", "LOG_LEVEL", "SHUTDOWN_TIMEOUT"}
	for _, env := range envVars {
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

func TestConfig_String(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.Config
		contains []string
	}{
		{
			name: "string representation contains all fields",
			config: &config.Config{
				GRPCPort:        50051,
				MetricsPort:     9090,
				LogLevel:        "info",
				ShutdownTimeout: 30 * time.Second,
			},
			contains: []string{
				"GRPCPort: 50051",
				"MetricsPort: 9090",
				"LogLevel: info",
				"ShutdownTimeout: 30s",
			},
		},
		{
			name: "string representation with custom values",
			config: &config.Config{
				GRPCPort:        8080,
				MetricsPort:     9091,
				LogLevel:        "debug",
				ShutdownTimeout: 60 * time.Second,
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

func TestConfig_MetricsAddress(t *testing.T) {
	tests := []struct {
		name        string
		metricsPort int
		want        string
	}{
		{
			name:        "default port",
			metricsPort: 9090,
			want:        ":9090",
		},
		{
			name:        "custom port",
			metricsPort: 9091,
			want:        ":9091",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			cfg := &config.Config{MetricsPort: tt.metricsPort}

			// Act
			result := cfg.MetricsAddress()

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
