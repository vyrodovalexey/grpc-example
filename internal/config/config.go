// Package config provides configuration management for the gRPC server.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// Auth mode constants.
	AuthModeNone = "none"
	AuthModeMTLS = "mtls"
	AuthModeOIDC = "oidc"
	AuthModeBoth = "both"

	// TLS mode constants.
	TLSModeNone = "none"
	TLSModeTLS  = "tls"
	TLSModeMTLS = "mtls"

	// Client auth constants.
	ClientAuthNone    = "none"
	ClientAuthRequest = "request"
	ClientAuthRequire = "require"

	// Default configuration values.
	defaultGRPCPort         = 50051
	defaultMetricsPort      = 9090
	defaultLogLevel         = "info"
	defaultShutdownTimeout  = 30 * time.Second
	defaultEnableReflection = true

	// Default TLS values.
	defaultTLSMode     = TLSModeNone
	defaultClientAuth  = ClientAuthNone
	defaultVaultPKITTL = 24 * time.Hour

	// Default auth mode.
	defaultAuthMode = AuthModeNone

	// Environment variable names.
	envGRPCPort         = "GRPC_PORT"
	envMetricsPort      = "METRICS_PORT"
	envLogLevel         = "LOG_LEVEL"
	envShutdownTimeout  = "SHUTDOWN_TIMEOUT"
	envEnableReflection = "ENABLE_REFLECTION"

	// TLS environment variable names.
	envTLSEnabled    = "TLS_ENABLED"
	envTLSMode       = "TLS_MODE"
	envTLSCertPath   = "TLS_CERT_PATH"
	envTLSKeyPath    = "TLS_KEY_PATH"
	envTLSCAPath     = "TLS_CA_PATH"
	envTLSClientAuth = "TLS_CLIENT_AUTH"

	// Vault PKI environment variable names.
	envVaultEnabled       = "VAULT_ENABLED"
	envVaultAddr          = "VAULT_ADDR"
	envVaultToken         = "VAULT_TOKEN"
	envVaultTokenFilePath = "VAULT_TOKEN_FILE"
	envVaultPKIPath       = "VAULT_PKI_PATH"
	envVaultPKIRole       = "VAULT_PKI_ROLE"
	envVaultPKITTL        = "VAULT_PKI_TTL"

	// OIDC environment variable names.
	envOIDCEnabled   = "OIDC_ENABLED"
	envOIDCIssuerURL = "OIDC_ISSUER_URL"
	envOIDCClientID  = "OIDC_CLIENT_ID"
	envOIDCAudience  = "OIDC_AUDIENCE"

	// Auth mode environment variable name.
	envAuthMode = "AUTH_MODE"

	// OTEL environment variable names.
	envOTELEnabled     = "OTEL_ENABLED"
	envOTELEndpoint    = "OTEL_EXPORTER_OTLP_ENDPOINT"
	envOTELServiceName = "OTEL_SERVICE_NAME"

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
	GRPCPort         int
	MetricsPort      int
	LogLevel         string
	ShutdownTimeout  time.Duration
	EnableReflection bool
	TLS              TLSConfig
	Auth             AuthConfig
	OTEL             OTELConfig
}

// OTELConfig holds OpenTelemetry configuration.
type OTELConfig struct {
	Enabled     bool
	Endpoint    string
	ServiceName string
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
		GRPCPort:         defaultGRPCPort,
		MetricsPort:      defaultMetricsPort,
		LogLevel:         defaultLogLevel,
		ShutdownTimeout:  defaultShutdownTimeout,
		EnableReflection: defaultEnableReflection,
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
		return nil, fmt.Errorf("loading config from environment: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
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

	if err := c.loadAuthModeEnv(); err != nil {
		return err
	}

	return c.loadOTELEnv()
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

	if val := os.Getenv(envEnableReflection); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envEnableReflection, err)
		}
		c.EnableReflection = enabled
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
	} else if tokenFilePath := os.Getenv(envVaultTokenFilePath); tokenFilePath != "" {
		cleanPath := filepath.Clean(tokenFilePath)
		//nolint:gosec // trusted env var, cleaned path
		tokenBytes, err := os.ReadFile(cleanPath)
		if err != nil {
			return fmt.Errorf("reading vault token file %s: %w", cleanPath, err)
		}
		c.TLS.VaultToken = strings.TrimSpace(string(tokenBytes))
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
// Returns error for consistency with other loadXxxEnv methods, though currently no parsing errors are possible.
func (c *Config) loadAuthModeEnv() error {
	if val := os.Getenv(envAuthMode); val != "" {
		c.Auth.Mode = val
	}

	return nil
}

// loadOTELEnv loads OpenTelemetry configuration from environment variables.
func (c *Config) loadOTELEnv() error {
	if val := os.Getenv(envOTELEnabled); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", envOTELEnabled, err)
		}
		c.OTEL.Enabled = enabled
	}

	if val := os.Getenv(envOTELEndpoint); val != "" {
		c.OTEL.Endpoint = val
	}

	if val := os.Getenv(envOTELServiceName); val != "" {
		c.OTEL.ServiceName = val
	}

	return nil
}

// applyDefaults sets default values for fields that are empty, ensuring backward compatibility.
// This is called after loading from environment and before validation.
func (c *Config) applyDefaults() {
	if c.TLS.Mode == "" {
		c.TLS.Mode = defaultTLSMode
	}

	if c.TLS.ClientAuth == "" {
		c.TLS.ClientAuth = defaultClientAuth
	}

	if c.Auth.Mode == "" {
		c.Auth.Mode = defaultAuthMode
	}
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
	if c.TLS.Mode == TLSModeMTLS && c.TLS.CAPath == "" && !c.TLS.VaultEnabled {
		return ErrTLSCARequired
	}

	return nil
}

// validateAuth validates authentication configuration.
func (c *Config) validateAuth() error {
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
	switch level {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

// isValidTLSMode checks if the TLS mode is valid.
func isValidTLSMode(mode string) bool {
	switch mode {
	case TLSModeNone, TLSModeTLS, TLSModeMTLS:
		return true
	default:
		return false
	}
}

// isValidClientAuth checks if the client auth mode is valid.
func isValidClientAuth(auth string) bool {
	switch auth {
	case ClientAuthNone, ClientAuthRequest, ClientAuthRequire:
		return true
	default:
		return false
	}
}

// isValidAuthMode checks if the auth mode is valid.
func isValidAuthMode(mode string) bool {
	switch mode {
	case AuthModeNone, AuthModeMTLS, AuthModeOIDC, AuthModeBoth:
		return true
	default:
		return false
	}
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
			sb.WriteString(fmt.Sprintf(", VaultAddr: %s, VaultToken: %s", sensitiveValueMask, sensitiveValueMask))
		}
	} else {
		sb.WriteString(", TLS: disabled")
	}

	sb.WriteString(fmt.Sprintf(", AuthMode: %s", c.Auth.Mode))

	if c.Auth.OIDCEnabled {
		sb.WriteString(fmt.Sprintf(
			", OIDC: enabled, OIDCIssuer: %s, OIDCClientID: %s, OIDCClientSecret: %s",
			sensitiveValueMask,
			sensitiveValueMask,
			sensitiveValueMask,
		))
	}

	if c.OTEL.Enabled {
		sb.WriteString(fmt.Sprintf(", OTEL: enabled, OTELEndpoint: %s, OTELServiceName: %s",
			c.OTEL.Endpoint, c.OTEL.ServiceName))
	}

	sb.WriteString("}")
	return sb.String()
}

// GRPCAddress returns the gRPC server address.
func (c *Config) GRPCAddress() string {
	return fmt.Sprintf(":%d", c.GRPCPort)
}
