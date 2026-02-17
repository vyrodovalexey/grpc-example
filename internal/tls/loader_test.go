// Package tls_test provides unit tests for the tls loader.
package tls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tlspkg "github.com/vyrodovalexey/grpc-example/internal/tls"
)

// generateTestCertAndKey generates a self-signed certificate and private key for testing.
// Returns the paths to the cert and key PEM files.
func generateTestCertAndKey(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	require.NoError(t, certFile.Close())

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	keyPath = filepath.Join(dir, "key.pem")
	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyFile.Close())

	return certPath, keyPath
}

// generateTestCA generates a CA certificate for testing.
// Returns the path to the CA PEM file.
func generateTestCA(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.pem")
	caFile, err := os.Create(caPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	require.NoError(t, caFile.Close())

	return caPath
}

func TestLoadCertificate(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) (certPath, keyPath string)
		wantErr     bool
		errContains string
	}{
		{
			name: "valid certificate and key",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				return generateTestCertAndKey(t, dir)
			},
			wantErr: false,
		},
		{
			name: "non-existent cert file",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				_, keyPath := generateTestCertAndKey(t, dir)
				return filepath.Join(dir, "nonexistent.pem"), keyPath
			},
			wantErr:     true,
			errContains: "loading certificate",
		},
		{
			name: "non-existent key file",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				certPath, _ := generateTestCertAndKey(t, dir)
				return certPath, filepath.Join(dir, "nonexistent.pem")
			},
			wantErr:     true,
			errContains: "loading certificate",
		},
		{
			name: "invalid cert content",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				_, keyPath := generateTestCertAndKey(t, dir)
				certPath := filepath.Join(dir, "invalid_cert.pem")
				require.NoError(t, os.WriteFile(certPath, []byte("not a cert"), 0o600))
				return certPath, keyPath
			},
			wantErr:     true,
			errContains: "loading certificate",
		},
		{
			name: "invalid key content",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				certPath, _ := generateTestCertAndKey(t, dir)
				keyPath := filepath.Join(dir, "invalid_key.pem")
				require.NoError(t, os.WriteFile(keyPath, []byte("not a key"), 0o600))
				return certPath, keyPath
			},
			wantErr:     true,
			errContains: "loading certificate",
		},
		{
			name: "empty cert file",
			setup: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				_, keyPath := generateTestCertAndKey(t, dir)
				certPath := filepath.Join(dir, "empty_cert.pem")
				require.NoError(t, os.WriteFile(certPath, []byte(""), 0o600))
				return certPath, keyPath
			},
			wantErr:     true,
			errContains: "loading certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			certPath, keyPath := tt.setup(t)

			// Act
			cert, err := tlspkg.LoadCertificate(certPath, keyPath)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, cert.Certificate)
			}
		})
	}
}

func TestLoadCACertPool(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid CA certificate",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				return generateTestCA(t, dir)
			},
			wantErr: false,
		},
		{
			name: "non-existent CA file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent.pem")
			},
			wantErr:     true,
			errContains: "reading CA certificate",
		},
		{
			name: "invalid PEM data",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				caPath := filepath.Join(dir, "invalid_ca.pem")
				require.NoError(t, os.WriteFile(caPath, []byte("not a certificate"), 0o600))
				return caPath
			},
			wantErr:     true,
			errContains: "no valid PEM data found",
		},
		{
			name: "empty CA file",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				caPath := filepath.Join(dir, "empty_ca.pem")
				require.NoError(t, os.WriteFile(caPath, []byte(""), 0o600))
				return caPath
			},
			wantErr:     true,
			errContains: "no valid PEM data found",
		},
		{
			name: "multiple CA certificates in one file",
			setup: func(t *testing.T) string {
				dir := t.TempDir()

				// Generate two CA certs
				key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				template1 := &x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{CommonName: "CA 1"},
					NotBefore:             time.Now(),
					NotAfter:              time.Now().Add(1 * time.Hour),
					KeyUsage:              x509.KeyUsageCertSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}
				template2 := &x509.Certificate{
					SerialNumber:          big.NewInt(2),
					Subject:               pkix.Name{CommonName: "CA 2"},
					NotBefore:             time.Now(),
					NotAfter:              time.Now().Add(1 * time.Hour),
					KeyUsage:              x509.KeyUsageCertSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}

				cert1DER, err := x509.CreateCertificate(rand.Reader, template1, template1, &key1.PublicKey, key1)
				require.NoError(t, err)
				cert2DER, err := x509.CreateCertificate(rand.Reader, template2, template2, &key2.PublicKey, key2)
				require.NoError(t, err)

				caPath := filepath.Join(dir, "multi_ca.pem")
				f, err := os.Create(caPath)
				require.NoError(t, err)
				require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert1DER}))
				require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert2DER}))
				require.NoError(t, f.Close())

				return caPath
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			caPath := tt.setup(t)

			// Act
			pool, err := tlspkg.LoadCACertPool(caPath)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, pool)
			} else {
				require.NoError(t, err)
				require.NotNil(t, pool)
			}
		})
	}
}
