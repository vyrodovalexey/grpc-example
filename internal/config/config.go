// Package config provides configuration management for the gRPC server.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	// Default configuration values.
	defaultGRPCPort        = 50051
	defaultMetricsPort     = 9090
	defaultLogLevel        = "info"
	defaultShutdownTimeout = 30 * time.Second

	// Environment variable names.
	envGRPCPort        = "GRPC_PORT"
	envMetricsPort     = "METRICS_PORT"
	envLogLevel        = "LOG_LEVEL"
	envShutdownTimeout = "SHUTDOWN_TIMEOUT"

	// Port range limits.
	minPort = 1
	maxPort = 65535
)

// Config holds the server configuration.
type Config struct {
	GRPCPort        int
	MetricsPort     int
	LogLevel        string
	ShutdownTimeout time.Duration
}

// Validation errors.
var (
	ErrInvalidGRPCPort        = errors.New("invalid gRPC port: must be between 1 and 65535")
	ErrInvalidMetricsPort     = errors.New("invalid metrics port: must be between 1 and 65535")
	ErrInvalidLogLevel        = errors.New("invalid log level: must be one of debug, info, warn, error")
	ErrInvalidShutdownTimeout = errors.New("invalid shutdown timeout: must be positive")
	ErrPortConflict           = errors.New("gRPC port and metrics port must be different")
)

// Load reads configuration from environment variables with defaults.
func Load() (*Config, error) {
	cfg := &Config{
		GRPCPort:        defaultGRPCPort,
		MetricsPort:     defaultMetricsPort,
		LogLevel:        defaultLogLevel,
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if err := cfg.loadFromEnv(); err != nil {
		return nil, fmt.Errorf("failed to load config from environment: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// loadFromEnv loads configuration values from environment variables.
func (c *Config) loadFromEnv() error {
	if val := os.Getenv(envGRPCPort); val != "" {
		port, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envGRPCPort, err)
		}
		c.GRPCPort = port
	}

	if val := os.Getenv(envMetricsPort); val != "" {
		port, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envMetricsPort, err)
		}
		c.MetricsPort = port
	}

	if val := os.Getenv(envLogLevel); val != "" {
		c.LogLevel = val
	}

	if val := os.Getenv(envShutdownTimeout); val != "" {
		timeout, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envShutdownTimeout, err)
		}
		c.ShutdownTimeout = timeout
	}

	return nil
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.GRPCPort < minPort || c.GRPCPort > maxPort {
		return ErrInvalidGRPCPort
	}

	if c.MetricsPort < minPort || c.MetricsPort > maxPort {
		return ErrInvalidMetricsPort
	}

	if c.GRPCPort == c.MetricsPort {
		return ErrPortConflict
	}

	if !isValidLogLevel(c.LogLevel) {
		return ErrInvalidLogLevel
	}

	if c.ShutdownTimeout <= 0 {
		return ErrInvalidShutdownTimeout
	}

	return nil
}

// isValidLogLevel checks if the log level is valid.
func isValidLogLevel(level string) bool {
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	return validLevels[level]
}

// String returns a string representation of the config, hiding sensitive data.
func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{GRPCPort: %d, MetricsPort: %d, LogLevel: %s, ShutdownTimeout: %s}",
		c.GRPCPort,
		c.MetricsPort,
		c.LogLevel,
		c.ShutdownTimeout,
	)
}

// GRPCAddress returns the gRPC server address.
func (c *Config) GRPCAddress() string {
	return fmt.Sprintf(":%d", c.GRPCPort)
}

// MetricsAddress returns the metrics server address.
func (c *Config) MetricsAddress() string {
	return fmt.Sprintf(":%d", c.MetricsPort)
}
