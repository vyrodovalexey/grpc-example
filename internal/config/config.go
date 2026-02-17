// Package config provides configuration management for the gRPC server.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// Default configuration values.
	defaultGRPCPort        = 50051
	defaultMetricsPort     = 9090
	defaultLogLevel        = "info"
	defaultShutdownTimeout = 30 * time.Second

	// Default TLS values.
	defaultTLSMode     = "none"
	defaultClientAuth  = "none"
	defaultVaultPKITTL = 24 * time.Hour

	// Default auth mode.
	defaultAuthMode = "none"

	// Environment variable names.
	envGRPCPort        = "GRPC_PORT"
	envMetricsPort     = "METRICS_PORT"
	envLogLevel        = "LOG_LEVEL"
	envShutdownTimeout = "SHUTDOWN_TIMEOUT"

	// TLS environment variable names.
	envTLSEnabled    = "TLS_ENABLED"
	envTLSMode       = "TLS_MODE"
	envTLSCertPath   = "TLS_CERT_PATH"
	envTLSKeyPath    = "TLS_KEY_PATH"
	envTLSCAPath     = "TLS_CA_PATH"
	envTLSClientAuth = "TLS_CLIENT_AUTH"

	// Vault PKI environment variable names.
	envVaultEnabled = "VAULT_ENABLED"
	envVaultAddr    = "VAULT_ADDR"
	envVaultToken   = "VAULT_TOKEN"
	envVaultPKIPath = "VAULT_PKI_PATH"
	envVaultPKIRole = "VAULT_PKI_ROLE"
	envVaultPKITTL  = "VAULT_PKI_TTL"

	// OIDC environment variable names.
	envOIDCEnabled   = "OIDC_ENABLED"
	envOIDCIssuerURL = "OIDC_ISSUER_URL"
	envOIDCClientID  = "OIDC_CLIENT_ID"
	envOIDCAudience  = "OIDC_AUDIENCE"

	// Auth mode environment variable name.
	envAuthMode = "AUTH_MODE"

	// Port range limits.
	minPort = 1
	maxPort = 65535

	// sensitiveValueMask is used to mask sensitive values in String() output.
	sensitiveValueMask = "****"
)

// envOIDCClientSecret is the environment variable for the OIDC client secret.
var envOIDCClientSecret = "OIDC_CLIENT_SECRET" //nolint:gosec // env var name, not a credential

// Config holds the server configuration.
type Config struct {
	GRPCPort        int
	MetricsPort     int
	LogLevel        string
	ShutdownTimeout time.Duration
	TLS             TLSConfig
	Auth            AuthConfig
}

// TLSConfig holds TLS-related configuration.
type TLSConfig struct {
	Enabled    bool
	Mode       string // "none", "tls", "mtls"
	CertPath   string
	KeyPath    string
	CAPath     string
	ClientAuth string // "none", "request", "require"

	// Vault PKI configuration.
	VaultEnabled bool
	VaultAddr    string
	VaultToken   string
	VaultPKIPath string
	VaultPKIRole string
	VaultPKITTL  time.Duration
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Mode             string // "none", "mtls", "oidc", "both"
	OIDCEnabled      bool
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCAudience     string
}

// Validation errors.
var (
	ErrInvalidGRPCPort        = errors.New("invalid gRPC port: must be between 1 and 65535")
	ErrInvalidMetricsPort     = errors.New("invalid metrics port: must be between 1 and 65535")
	ErrInvalidLogLevel        = errors.New("invalid log level: must be one of debug, info, warn, error")
	ErrInvalidShutdownTimeout = errors.New("invalid shutdown timeout: must be positive")
	ErrPortConflict           = errors.New("gRPC port and metrics port must be different")
	ErrTLSCertRequired        = errors.New("TLS certificate path is required when TLS is enabled and Vault is disabled")
	ErrTLSKeyRequired         = errors.New("TLS key path is required when TLS is enabled and Vault is disabled")
	ErrTLSCARequired          = errors.New("TLS CA path is required for mTLS mode")
	ErrOIDCIssuerRequired     = errors.New("OIDC issuer URL is required when OIDC is enabled")
	ErrOIDCClientIDRequired   = errors.New("OIDC client ID is required when OIDC is enabled")
	ErrInvalidTLSMode         = errors.New("invalid TLS mode: must be one of none, tls, mtls")
	ErrInvalidClientAuth      = errors.New("invalid client auth: must be one of none, request, require")
	ErrInvalidAuthMode        = errors.New("invalid auth mode: must be one of none, mtls, oidc, both")
)

// Load reads configuration from environment variables with defaults.
func Load() (*Config, error) {
	cfg := &Config{
		GRPCPort:        defaultGRPCPort,
		MetricsPort:     defaultMetricsPort,
		LogLevel:        defaultLogLevel,
		ShutdownTimeout: defaultShutdownTimeout,
		TLS: TLSConfig{
			Mode:        defaultTLSMode,
			ClientAuth:  defaultClientAuth,
			VaultPKITTL: defaultVaultPKITTL,
		},
		Auth: AuthConfig{
			Mode: defaultAuthMode,
		},
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
	if err := c.loadBaseEnv(); err != nil {
		return err
	}

	if err := c.loadTLSEnv(); err != nil {
		return err
	}

	if err := c.loadVaultEnv(); err != nil {
		return err
	}

	if err := c.loadOIDCEnv(); err != nil {
		return err
	}

	return c.loadAuthModeEnv()
}

// loadBaseEnv loads base server configuration from environment variables.
func (c *Config) loadBaseEnv() error {
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

// loadTLSEnv loads TLS configuration from environment variables.
func (c *Config) loadTLSEnv() error {
	if val := os.Getenv(envTLSEnabled); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envTLSEnabled, err)
		}
		c.TLS.Enabled = enabled
	}

	if val := os.Getenv(envTLSMode); val != "" {
		c.TLS.Mode = val
	}

	if val := os.Getenv(envTLSCertPath); val != "" {
		c.TLS.CertPath = val
	}

	if val := os.Getenv(envTLSKeyPath); val != "" {
		c.TLS.KeyPath = val
	}

	if val := os.Getenv(envTLSCAPath); val != "" {
		c.TLS.CAPath = val
	}

	if val := os.Getenv(envTLSClientAuth); val != "" {
		c.TLS.ClientAuth = val
	}

	return nil
}

// loadVaultEnv loads Vault PKI configuration from environment variables.
func (c *Config) loadVaultEnv() error {
	if val := os.Getenv(envVaultEnabled); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envVaultEnabled, err)
		}
		c.TLS.VaultEnabled = enabled
	}

	if val := os.Getenv(envVaultAddr); val != "" {
		c.TLS.VaultAddr = val
	}

	if val := os.Getenv(envVaultToken); val != "" {
		c.TLS.VaultToken = val
	}

	if val := os.Getenv(envVaultPKIPath); val != "" {
		c.TLS.VaultPKIPath = val
	}

	if val := os.Getenv(envVaultPKIRole); val != "" {
		c.TLS.VaultPKIRole = val
	}

	if val := os.Getenv(envVaultPKITTL); val != "" {
		ttl, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envVaultPKITTL, err)
		}
		c.TLS.VaultPKITTL = ttl
	}

	return nil
}

// loadOIDCEnv loads OIDC configuration from environment variables.
func (c *Config) loadOIDCEnv() error {
	if val := os.Getenv(envOIDCEnabled); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envOIDCEnabled, err)
		}
		c.Auth.OIDCEnabled = enabled
	}

	if val := os.Getenv(envOIDCIssuerURL); val != "" {
		c.Auth.OIDCIssuerURL = val
	}

	if val := os.Getenv(envOIDCClientID); val != "" {
		c.Auth.OIDCClientID = val
	}

	if val := os.Getenv(envOIDCClientSecret); val != "" {
		c.Auth.OIDCClientSecret = val
	}

	if val := os.Getenv(envOIDCAudience); val != "" {
		c.Auth.OIDCAudience = val
	}

	return nil
}

// loadAuthModeEnv loads auth mode configuration from environment variables.
func (c *Config) loadAuthModeEnv() error {
	if val := os.Getenv(envAuthMode); val != "" {
		c.Auth.Mode = val
	}

	return nil
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if err := c.validateBase(); err != nil {
		return err
	}

	if err := c.validateTLS(); err != nil {
		return err
	}

	return c.validateAuth()
}

// validateBase validates base server configuration.
func (c *Config) validateBase() error {
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

// validateTLS validates TLS configuration.
func (c *Config) validateTLS() error {
	if !c.TLS.Enabled {
		return nil
	}

	// Treat empty TLS mode as "none" for backward compatibility.
	if c.TLS.Mode == "" {
		c.TLS.Mode = defaultTLSMode
	}

	// Treat empty client auth as "none" for backward compatibility.
	if c.TLS.ClientAuth == "" {
		c.TLS.ClientAuth = defaultClientAuth
	}

	if !isValidTLSMode(c.TLS.Mode) {
		return ErrInvalidTLSMode
	}

	if !isValidClientAuth(c.TLS.ClientAuth) {
		return ErrInvalidClientAuth
	}

	// When Vault is not enabled, cert and key paths are required.
	if !c.TLS.VaultEnabled {
		if c.TLS.CertPath == "" {
			return ErrTLSCertRequired
		}
		if c.TLS.KeyPath == "" {
			return ErrTLSKeyRequired
		}
	}

	// For mTLS mode, CA path is required (unless Vault provides it).
	if c.TLS.Mode == "mtls" && c.TLS.CAPath == "" && !c.TLS.VaultEnabled {
		return ErrTLSCARequired
	}

	return nil
}

// validateAuth validates authentication configuration.
func (c *Config) validateAuth() error {
	// Treat empty auth mode as "none" for backward compatibility.
	if c.Auth.Mode == "" {
		c.Auth.Mode = defaultAuthMode
	}

	if !isValidAuthMode(c.Auth.Mode) {
		return ErrInvalidAuthMode
	}

	if !c.Auth.OIDCEnabled {
		return nil
	}

	if c.Auth.OIDCIssuerURL == "" {
		return ErrOIDCIssuerRequired
	}

	if c.Auth.OIDCClientID == "" {
		return ErrOIDCClientIDRequired
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

// isValidTLSMode checks if the TLS mode is valid.
func isValidTLSMode(mode string) bool {
	validModes := map[string]bool{
		"none": true,
		"tls":  true,
		"mtls": true,
	}
	return validModes[mode]
}

// isValidClientAuth checks if the client auth mode is valid.
func isValidClientAuth(auth string) bool {
	validAuths := map[string]bool{
		"none":    true,
		"request": true,
		"require": true,
	}
	return validAuths[auth]
}

// isValidAuthMode checks if the auth mode is valid.
func isValidAuthMode(mode string) bool {
	validModes := map[string]bool{
		"none": true,
		"mtls": true,
		"oidc": true,
		"both": true,
	}
	return validModes[mode]
}

// String returns a string representation of the config, hiding sensitive data.
func (c *Config) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(
		"Config{GRPCPort: %d, MetricsPort: %d, LogLevel: %s, ShutdownTimeout: %s",
		c.GRPCPort,
		c.MetricsPort,
		c.LogLevel,
		c.ShutdownTimeout,
	))

	if c.TLS.Enabled {
		sb.WriteString(fmt.Sprintf(", TLS: enabled, TLSMode: %s", c.TLS.Mode))
		if c.TLS.VaultEnabled {
			sb.WriteString(fmt.Sprintf(", VaultAddr: %s, VaultToken: %s", c.TLS.VaultAddr, sensitiveValueMask))
		}
	} else {
		sb.WriteString(", TLS: disabled")
	}

	sb.WriteString(fmt.Sprintf(", AuthMode: %s", c.Auth.Mode))

	if c.Auth.OIDCEnabled {
		sb.WriteString(fmt.Sprintf(
			", OIDC: enabled, OIDCIssuer: %s, OIDCClientSecret: %s",
			c.Auth.OIDCIssuerURL,
			sensitiveValueMask,
		))
	}

	sb.WriteString("}")
	return sb.String()
}

// GRPCAddress returns the gRPC server address.
func (c *Config) GRPCAddress() string {
	return fmt.Sprintf(":%d", c.GRPCPort)
}

// MetricsAddress returns the metrics server address.
func (c *Config) MetricsAddress() string {
	return fmt.Sprintf(":%d", c.MetricsPort)
}
