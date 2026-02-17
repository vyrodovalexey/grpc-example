package tls

import (
	"crypto/tls"
	"fmt"

	"github.com/vyrodovalexey/grpc-example/internal/config"
)

// clientAuthMap maps string client auth values to tls.ClientAuthType.
var clientAuthMap = map[string]tls.ClientAuthType{
	"none":    tls.NoClientCert,
	"request": tls.RequestClientCert,
	"require": tls.RequireAndVerifyClientCert,
}

// BuildServerTLSConfig constructs a *tls.Config from the application's TLSConfig.
// It supports TLS mode (server-only certs) and mTLS mode (require client certs).
func BuildServerTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	cert, err := LoadCertificate(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Set client auth type.
	clientAuth, ok := clientAuthMap[cfg.ClientAuth]
	if !ok {
		return nil, fmt.Errorf("unsupported client auth type: %s", cfg.ClientAuth)
	}
	tlsConfig.ClientAuth = clientAuth

	// For mTLS mode, load CA cert pool for client certificate verification.
	if cfg.Mode == "mtls" {
		if cfg.CAPath == "" {
			return nil, fmt.Errorf("CA certificate path is required for mTLS mode")
		}

		caPool, caErr := LoadCACertPool(cfg.CAPath)
		if caErr != nil {
			return nil, fmt.Errorf("loading CA certificate for mTLS: %w", caErr)
		}
		tlsConfig.ClientCAs = caPool

		// Override client auth to require and verify for mTLS if not explicitly set.
		if cfg.ClientAuth == "none" {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return tlsConfig, nil
}
