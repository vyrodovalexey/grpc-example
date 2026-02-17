// Package tls provides TLS configuration, certificate loading, and Vault PKI integration.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/config"
	"github.com/vyrodovalexey/grpc-example/internal/retry"
)

const (
	// vaultClientTimeout is the timeout for Vault HTTP client operations.
	vaultClientTimeout = 30 * time.Second
)

// VaultPKIClient defines the interface for Vault PKI operations.
type VaultPKIClient interface {
	// IssueCertificate issues a new certificate from Vault PKI.
	IssueCertificate(ctx context.Context, commonName string) (tls.Certificate, string, error)
	// GetCACertificate retrieves the CA certificate from Vault PKI.
	GetCACertificate(ctx context.Context) (*x509.CertPool, error)
}

// vaultPKIClient implements VaultPKIClient using the Vault API.
type vaultPKIClient struct {
	client  *vault.Client
	pkiPath string
	pkiRole string
	pkiTTL  string
	logger  *zap.Logger
}

// NewVaultPKIClient creates a new Vault PKI client.
func NewVaultPKIClient(cfg config.TLSConfig, logger *zap.Logger) (VaultPKIClient, error) {
	if cfg.VaultAddr == "" {
		return nil, fmt.Errorf("vault address is required")
	}

	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = cfg.VaultAddr
	vaultCfg.Timeout = vaultClientTimeout

	client, err := vault.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	client.SetToken(cfg.VaultToken)

	return &vaultPKIClient{
		client:  client,
		pkiPath: cfg.VaultPKIPath,
		pkiRole: cfg.VaultPKIRole,
		pkiTTL:  cfg.VaultPKITTL.String(),
		logger:  logger.Named("vault_pki"),
	}, nil
}

// IssueCertificate issues a new certificate from Vault PKI with exponential backoff retry.
// Returns the TLS certificate, the CA certificate PEM string, and any error.
func (v *vaultPKIClient) IssueCertificate(ctx context.Context, commonName string) (tls.Certificate, string, error) {
	path := fmt.Sprintf("%s/issue/%s", v.pkiPath, v.pkiRole)
	data := map[string]any{
		"common_name": commonName,
		"ttl":         v.pkiTTL,
	}

	var secret *vault.Secret

	err := retry.Do(ctx, retry.DefaultConfig(), v.logger, "vault PKI request", func() error {
		var writeErr error
		secret, writeErr = v.client.Logical().WriteWithContext(ctx, path, data)
		return writeErr
	})
	if err != nil {
		return tls.Certificate{}, "", err
	}

	if secret == nil || secret.Data == nil {
		return tls.Certificate{}, "", fmt.Errorf("vault returned empty response for certificate issuance")
	}

	return v.parseCertificateResponse(secret)
}

// GetCACertificate retrieves the CA certificate from Vault PKI with exponential backoff retry.
func (v *vaultPKIClient) GetCACertificate(ctx context.Context) (*x509.CertPool, error) {
	path := fmt.Sprintf("%s/cert/ca", v.pkiPath)

	var secret *vault.Secret

	err := retry.Do(ctx, retry.DefaultConfig(), v.logger, "vault CA retrieval", func() error {
		var readErr error
		secret, readErr = v.client.Logical().ReadWithContext(ctx, path)
		return readErr
	})
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault returned empty response for CA certificate")
	}

	caPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("vault CA response missing certificate field")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("parsing CA certificate from vault")
	}

	v.logger.Info("retrieved CA certificate from vault")
	return pool, nil
}

// parseCertificateResponse parses the Vault PKI issue response into a tls.Certificate.
func (v *vaultPKIClient) parseCertificateResponse(secret *vault.Secret) (tls.Certificate, string, error) {
	certPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return tls.Certificate{}, "", fmt.Errorf("vault response missing certificate field")
	}

	keyPEM, ok := secret.Data["private_key"].(string)
	if !ok {
		return tls.Certificate{}, "", fmt.Errorf("vault response missing private_key field")
	}

	caPEM, _ := secret.Data["issuing_ca"].(string)

	// Validate PEM data.
	if block, _ := pem.Decode([]byte(certPEM)); block == nil {
		return tls.Certificate{}, "", fmt.Errorf("invalid certificate PEM from vault")
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("parsing certificate from vault: %w", err)
	}

	v.logger.Info("issued certificate from vault",
		zap.String("pki_path", v.pkiPath),
		zap.String("pki_role", v.pkiRole),
	)

	return cert, caPEM, nil
}
