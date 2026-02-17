// Package tls_test provides unit tests for the vault PKI client.
package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/config"
	tlspkg "github.com/vyrodovalexey/grpc-example/internal/tls"
)

// generatePEMCertAndKey generates a PEM-encoded certificate and private key for testing.
func generatePEMCertAndKey(t *testing.T) (certPEM, keyPEM, caPEM string) {
	t.Helper()

	// Generate CA key and cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
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

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate server key and cert signed by CA.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test-server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})

	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEMBlock), string(keyPEMBlock), string(caPEMBlock)
}

// vaultResponse wraps a Vault API response.
type vaultResponse struct {
	Data map[string]any `json:"data"`
}

func TestNewVaultPKIClient(t *testing.T) {
	tests := []struct {
		name        string
		cfg         config.TLSConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid configuration",
			cfg: config.TLSConfig{
				VaultAddr:    "http://127.0.0.1:8200",
				VaultToken:   "test-token",
				VaultPKIPath: "pki",
				VaultPKIRole: "server",
				VaultPKITTL:  24 * time.Hour,
			},
			wantErr: false,
		},
		{
			name: "empty vault address",
			cfg: config.TLSConfig{
				VaultAddr:    "",
				VaultToken:   "test-token",
				VaultPKIPath: "pki",
				VaultPKIRole: "server",
				VaultPKITTL:  24 * time.Hour,
			},
			wantErr:     true,
			errContains: "vault address is required",
		},
		{
			name: "valid configuration with custom TTL",
			cfg: config.TLSConfig{
				VaultAddr:    "https://vault.example.com:8200",
				VaultToken:   "s.abcdef123456",
				VaultPKIPath: "pki/intermediate",
				VaultPKIRole: "grpc-server",
				VaultPKITTL:  48 * time.Hour,
			},
			wantErr: false,
		},
		{
			name: "valid configuration with empty token",
			cfg: config.TLSConfig{
				VaultAddr:    "http://127.0.0.1:8200",
				VaultToken:   "",
				VaultPKIPath: "pki",
				VaultPKIRole: "server",
				VaultPKITTL:  24 * time.Hour,
			},
			wantErr: false, // Empty token is allowed at creation time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := zap.NewNop()

			// Act
			client, err := tlspkg.NewVaultPKIClient(tt.cfg, logger)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				require.NotNil(t, client)
			}
		})
	}
}

func TestVaultPKIClient_ImplementsInterface(t *testing.T) {
	// Arrange
	logger := zap.NewNop()
	cfg := config.TLSConfig{
		VaultAddr:    "http://127.0.0.1:8200",
		VaultToken:   "test-token",
		VaultPKIPath: "pki",
		VaultPKIRole: "server",
		VaultPKITTL:  24 * time.Hour,
	}

	// Act
	client, err := tlspkg.NewVaultPKIClient(cfg, logger)

	// Assert
	require.NoError(t, err)
	var _ tlspkg.VaultPKIClient = client
}

func TestVaultPKIClient_IssueCertificate(t *testing.T) {
	certPEM, keyPEM, caPEM := generatePEMCertAndKey(t)

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name: "successful certificate issuance",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := vaultResponse{
					Data: map[string]any{
						"certificate": certPEM,
						"private_key": keyPEM,
						"issuing_ca":  caPEM,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantErr: false,
		},
		{
			name: "vault returns empty response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			},
			wantErr:     true,
			errContains: "vault returned empty response",
		},
		{
			name: "vault returns response without certificate field",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := vaultResponse{
					Data: map[string]any{
						"private_key": keyPEM,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantErr:     true,
			errContains: "missing certificate field",
		},
		{
			name: "vault returns response without private_key field",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := vaultResponse{
					Data: map[string]any{
						"certificate": certPEM,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantErr:     true,
			errContains: "missing private_key field",
		},
		{
			name: "vault returns invalid certificate PEM",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := vaultResponse{
					Data: map[string]any{
						"certificate": "not-a-valid-pem",
						"private_key": keyPEM,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantErr:     true,
			errContains: "invalid certificate PEM",
		},
		{
			name: "vault returns mismatched cert and key",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Generate a different key that doesn't match the cert
				otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				otherKeyDER, _ := x509.MarshalECPrivateKey(otherKey)
				otherKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherKeyDER}))

				resp := vaultResponse{
					Data: map[string]any{
						"certificate": certPEM,
						"private_key": otherKeyPEM,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantErr:     true,
			errContains: "parsing certificate from vault",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			logger := zap.NewNop()
			cfg := config.TLSConfig{
				VaultAddr:    srv.URL,
				VaultToken:   "test-token",
				VaultPKIPath: "pki",
				VaultPKIRole: "server",
				VaultPKITTL:  24 * time.Hour,
			}

			client, err := tlspkg.NewVaultPKIClient(cfg, logger)
			require.NoError(t, err)

			// Act
			cert, caCertPEM, issueErr := client.IssueCertificate(context.Background(), "test-server")

			// Assert
			if tt.wantErr {
				require.Error(t, issueErr)
				assert.Contains(t, issueErr.Error(), tt.errContains)
			} else {
				require.NoError(t, issueErr)
				assert.NotEmpty(t, cert.Certificate)
				assert.Equal(t, caPEM, caCertPEM)
			}
		})
	}
}

func TestVaultPKIClient_IssueCertificate_ContextCancelled(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow response to trigger context cancellation
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.TLSConfig{
		VaultAddr:    srv.URL,
		VaultToken:   "test-token",
		VaultPKIPath: "pki",
		VaultPKIRole: "server",
		VaultPKITTL:  24 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Act
	_, _, issueErr := client.IssueCertificate(ctx, "test-server")

	// Assert
	require.Error(t, issueErr)
	assert.Contains(t, issueErr.Error(), "context cancelled")
}

func TestVaultPKIClient_IssueCertificate_ServerError(t *testing.T) {
	// Arrange - server that always returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.TLSConfig{
		VaultAddr:    srv.URL,
		VaultToken:   "test-token",
		VaultPKIPath: "pki",
		VaultPKIRole: "server",
		VaultPKITTL:  24 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, logger)
	require.NoError(t, err)

	// Use a context that cancels quickly to avoid waiting for all retries
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Act
	_, _, issueErr := client.IssueCertificate(ctx, "test-server")

	// Assert
	require.Error(t, issueErr)
}

func TestVaultPKIClient_GetCACertificate(t *testing.T) {
	_, _, caPEM := generatePEMCertAndKey(t)

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name: "successful CA retrieval",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := vaultResponse{
					Data: map[string]any{
						"certificate": caPEM,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantErr: false,
		},
		{
			name: "vault returns empty response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			},
			wantErr:     true,
			errContains: "vault returned empty response",
		},
		{
			name: "vault returns response without certificate field",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := vaultResponse{
					Data: map[string]any{
						"other_field": "value",
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantErr:     true,
			errContains: "missing certificate field",
		},
		{
			name: "vault returns invalid CA PEM",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := vaultResponse{
					Data: map[string]any{
						"certificate": "not-a-valid-pem",
					},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantErr:     true,
			errContains: "parsing CA certificate from vault",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			logger := zap.NewNop()
			cfg := config.TLSConfig{
				VaultAddr:    srv.URL,
				VaultToken:   "test-token",
				VaultPKIPath: "pki",
				VaultPKIRole: "server",
				VaultPKITTL:  24 * time.Hour,
			}

			client, err := tlspkg.NewVaultPKIClient(cfg, logger)
			require.NoError(t, err)

			// Act
			pool, caErr := client.GetCACertificate(context.Background())

			// Assert
			if tt.wantErr {
				require.Error(t, caErr)
				assert.Contains(t, caErr.Error(), tt.errContains)
				assert.Nil(t, pool)
			} else {
				require.NoError(t, caErr)
				require.NotNil(t, pool)
			}
		})
	}
}

func TestVaultPKIClient_GetCACertificate_ContextCancelled(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.TLSConfig{
		VaultAddr:    srv.URL,
		VaultToken:   "test-token",
		VaultPKIPath: "pki",
		VaultPKIRole: "server",
		VaultPKITTL:  24 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Act
	pool, caErr := client.GetCACertificate(ctx)

	// Assert
	require.Error(t, caErr)
	assert.Nil(t, pool)
	assert.Contains(t, caErr.Error(), "context cancelled")
}

func TestVaultPKIClient_GetCACertificate_ServerError(t *testing.T) {
	// Arrange - server that always returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.TLSConfig{
		VaultAddr:    srv.URL,
		VaultToken:   "test-token",
		VaultPKIPath: "pki",
		VaultPKIRole: "server",
		VaultPKITTL:  24 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, logger)
	require.NoError(t, err)

	// Use a context that cancels quickly to avoid waiting for all retries
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Act
	pool, caErr := client.GetCACertificate(ctx)

	// Assert
	require.Error(t, caErr)
	assert.Nil(t, pool)
}

func TestVaultPKIClient_IssueCertificate_WithoutIssuingCA(t *testing.T) {
	// Arrange - response without issuing_ca field
	certPEM, keyPEM, _ := generatePEMCertAndKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := vaultResponse{
			Data: map[string]any{
				"certificate": certPEM,
				"private_key": keyPEM,
				// No issuing_ca field
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	logger := zap.NewNop()
	cfg := config.TLSConfig{
		VaultAddr:    srv.URL,
		VaultToken:   "test-token",
		VaultPKIPath: "pki",
		VaultPKIRole: "server",
		VaultPKITTL:  24 * time.Hour,
	}

	client, err := tlspkg.NewVaultPKIClient(cfg, logger)
	require.NoError(t, err)

	// Act
	cert, caCertPEM, issueErr := client.IssueCertificate(context.Background(), "test-server")

	// Assert - should succeed, caPEM will be empty
	require.NoError(t, issueErr)
	assert.NotEmpty(t, cert.Certificate)
	assert.Empty(t, caCertPEM)
}
