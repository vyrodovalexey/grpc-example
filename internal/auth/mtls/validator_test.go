// Package mtls_test provides unit tests for the mtls validator.
package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
)

// createPeerContext creates a context with peer info containing TLS certificate data.
func createPeerContext(cert *x509.Certificate) context.Context {
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{
				{cert},
			},
		},
	}
	p := &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		AuthInfo: tlsInfo,
	}
	return peer.NewContext(context.Background(), p)
}

// createTestCert creates a test x509 certificate with the given parameters.
func createTestCert(cn string, org []string, ou []string, dnsNames []string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       org,
			OrganizationalUnit: ou,
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(serial),
	}
}

func TestValidatePeerCertificate(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		cfg         mtls.Config
		wantErr     bool
		errContains string
		validate    func(t *testing.T, identity any)
	}{
		{
			name: "valid certificate - no restrictions",
			ctx: createPeerContext(createTestCert(
				"client1",
				[]string{"TestOrg"},
				[]string{"Engineering"},
				[]string{"client1.example.com"},
				12345,
			)),
			cfg:     mtls.Config{},
			wantErr: false,
			validate: func(t *testing.T, identity any) {
				// Validated via return value in test body
			},
		},
		{
			name: "valid certificate - allowed subject matches",
			ctx: createPeerContext(createTestCert(
				"client1",
				[]string{"TestOrg"},
				[]string{"Engineering"},
				nil,
				12345,
			)),
			cfg: mtls.Config{
				AllowedSubjects: []string{"client1", "client2"},
			},
			wantErr: false,
		},
		{
			name: "valid certificate - allowed SAN matches",
			ctx: createPeerContext(createTestCert(
				"client1",
				nil,
				nil,
				[]string{"client1.example.com", "other.example.com"},
				12345,
			)),
			cfg: mtls.Config{
				AllowedSANs: []string{"client1.example.com"},
			},
			wantErr: false,
		},
		{
			name: "valid certificate - allowed OU matches",
			ctx: createPeerContext(createTestCert(
				"client1",
				nil,
				[]string{"Engineering"},
				nil,
				12345,
			)),
			cfg: mtls.Config{
				AllowedOUs: []string{"Engineering", "Operations"},
			},
			wantErr: false,
		},
		{
			name: "rejected - subject not in allowed list",
			ctx: createPeerContext(createTestCert(
				"unauthorized-client",
				nil,
				nil,
				nil,
				12345,
			)),
			cfg: mtls.Config{
				AllowedSubjects: []string{"client1", "client2"},
			},
			wantErr:     true,
			errContains: "not in allowed subjects",
		},
		{
			name: "rejected - SAN not in allowed list",
			ctx: createPeerContext(createTestCert(
				"client1",
				nil,
				nil,
				[]string{"unknown.example.com"},
				12345,
			)),
			cfg: mtls.Config{
				AllowedSANs: []string{"client1.example.com"},
			},
			wantErr:     true,
			errContains: "do not match allowed SANs",
		},
		{
			name: "rejected - OU not in allowed list",
			ctx: createPeerContext(createTestCert(
				"client1",
				nil,
				[]string{"Marketing"},
				nil,
				12345,
			)),
			cfg: mtls.Config{
				AllowedOUs: []string{"Engineering"},
			},
			wantErr:     true,
			errContains: "not in allowed OUs",
		},
		{
			name:        "no peer info in context",
			ctx:         context.Background(),
			cfg:         mtls.Config{},
			wantErr:     true,
			errContains: "no peer info",
		},
		{
			name: "peer without TLS info",
			ctx: func() context.Context {
				p := &peer.Peer{
					Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
				}
				return peer.NewContext(context.Background(), p)
			}(),
			cfg:         mtls.Config{},
			wantErr:     true,
			errContains: "does not have TLS info",
		},
		{
			name: "TLS info with no verified chains",
			ctx: func() context.Context {
				tlsInfo := credentials.TLSInfo{
					State: tls.ConnectionState{
						VerifiedChains: nil,
					},
				}
				p := &peer.Peer{
					Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
					AuthInfo: tlsInfo,
				}
				return peer.NewContext(context.Background(), p)
			}(),
			cfg:         mtls.Config{},
			wantErr:     true,
			errContains: "no verified client certificate",
		},
		{
			name: "TLS info with empty verified chains",
			ctx: func() context.Context {
				tlsInfo := credentials.TLSInfo{
					State: tls.ConnectionState{
						VerifiedChains: [][]*x509.Certificate{},
					},
				}
				p := &peer.Peer{
					Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
					AuthInfo: tlsInfo,
				}
				return peer.NewContext(context.Background(), p)
			}(),
			cfg:         mtls.Config{},
			wantErr:     true,
			errContains: "no verified client certificate",
		},
		{
			name: "TLS info with empty first chain",
			ctx: func() context.Context {
				tlsInfo := credentials.TLSInfo{
					State: tls.ConnectionState{
						VerifiedChains: [][]*x509.Certificate{
							{},
						},
					},
				}
				p := &peer.Peer{
					Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
					AuthInfo: tlsInfo,
				}
				return peer.NewContext(context.Background(), p)
			}(),
			cfg:         mtls.Config{},
			wantErr:     true,
			errContains: "no verified client certificate",
		},
		{
			name: "certificate with no org or OU - claims still populated",
			ctx: createPeerContext(createTestCert(
				"simple-client",
				nil,
				nil,
				nil,
				99999,
			)),
			cfg:     mtls.Config{},
			wantErr: false,
		},
		{
			name: "empty SANs with SAN restriction - rejected",
			ctx: createPeerContext(createTestCert(
				"client1",
				nil,
				nil,
				nil, // no DNS names
				12345,
			)),
			cfg: mtls.Config{
				AllowedSANs: []string{"client1.example.com"},
			},
			wantErr:     true,
			errContains: "do not match allowed SANs",
		},
		{
			name: "empty OUs with OU restriction - rejected",
			ctx: createPeerContext(createTestCert(
				"client1",
				nil,
				nil, // no OUs
				nil,
				12345,
			)),
			cfg: mtls.Config{
				AllowedOUs: []string{"Engineering"},
			},
			wantErr:     true,
			errContains: "not in allowed OUs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			identity, err := mtls.ValidatePeerCertificate(tt.ctx, tt.cfg)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, identity)
			} else {
				require.NoError(t, err)
				require.NotNil(t, identity)
				assert.Equal(t, "mtls", identity.AuthMethod)
				assert.NotEmpty(t, identity.Claims["serial"])
			}
		})
	}
}

func TestValidatePeerCertificate_IdentityFields(t *testing.T) {
	// Arrange
	cert := createTestCert(
		"test-client",
		[]string{"TestOrg"},
		[]string{"Engineering"},
		[]string{"test.example.com"},
		54321,
	)
	ctx := createPeerContext(cert)
	cfg := mtls.Config{}

	// Act
	identity, err := mtls.ValidatePeerCertificate(ctx, cfg)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "test-client", identity.Subject)
	assert.Equal(t, "Test CA", identity.Issuer)
	assert.Equal(t, "mtls", identity.AuthMethod)
	assert.Equal(t, "TestOrg", identity.Claims["org"])
	assert.Equal(t, "Engineering", identity.Claims["ou"])
	assert.Equal(t, "54321", identity.Claims["serial"])
}

func TestValidatePeerCertificate_NoOrgNorOU(t *testing.T) {
	// Arrange - certificate with no org or OU
	cert := createTestCert("bare-client", nil, nil, nil, 11111)
	ctx := createPeerContext(cert)
	cfg := mtls.Config{}

	// Act
	identity, err := mtls.ValidatePeerCertificate(ctx, cfg)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "bare-client", identity.Subject)
	_, hasOrg := identity.Claims["org"]
	assert.False(t, hasOrg, "org claim should not be present when Organization is empty")
	_, hasOU := identity.Claims["ou"]
	assert.False(t, hasOU, "ou claim should not be present when OrganizationalUnit is empty")
	assert.Equal(t, "11111", identity.Claims["serial"])
}
