// Package tls provides TLS configuration, certificate loading, and Vault PKI integration.
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadCertificate loads an X.509 certificate and private key from PEM files.
func LoadCertificate(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading certificate from %s and %s: %w", certPath, keyPath, err)
	}

	return cert, nil
}

// LoadCACertPool loads CA certificate(s) from a PEM file into an x509.CertPool.
// The PEM file may contain multiple CA certificates.
func LoadCACertPool(caPath string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caPath) //nolint:gosec // CA path is from validated config
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate from %s: %w", caPath, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s: no valid PEM data found", caPath)
	}

	return pool, nil
}
