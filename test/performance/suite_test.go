//go:build performance

// Package performance provides performance and benchmark tests for authentication overhead.
package performance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
	authoidc "github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

// TestMain is the entry point for performance tests.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// Test service implementation for benchmarks
// ---------------------------------------------------------------------------

type benchTestService struct {
	apiv1.UnimplementedTestServiceServer
}

func (s *benchTestService) Unary(_ context.Context, req *apiv1.UnaryRequest) (*apiv1.UnaryResponse, error) {
	return &apiv1.UnaryResponse{
		Message:   req.GetMessage(),
		Timestamp: time.Now().UnixNano(),
	}, nil
}

// ---------------------------------------------------------------------------
// CA and certificate helpers (same as functional tests)
// ---------------------------------------------------------------------------

type benchCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	pool    *x509.CertPool
}

func newBenchCA() (*benchCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Bench CA",
			Organization: []string{"Bench Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &benchCA{cert: cert, key: key, certPEM: certPEM, pool: pool}, nil
}

func (ca *benchCA) issueCert(cn string, dnsNames []string, ips []net.IP) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ---------------------------------------------------------------------------
// Server setup helpers
// ---------------------------------------------------------------------------

// insecureServer creates an insecure gRPC server and returns address + cleanup.
func insecureServer(b *testing.B) (string, func()) {
	b.Helper()

	srv := grpc.NewServer()
	apiv1.RegisterTestServiceServer(srv, &benchTestService{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}

	go func() { _ = srv.Serve(lis) }()

	return lis.Addr().String(), srv.Stop
}

// tlsServer creates a TLS-only gRPC server (no client auth).
func tlsServer(b *testing.B, ca *benchCA) (string, func()) {
	b.Helper()

	serverCert, err := ca.issueCert("bench-server", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatalf("issue server cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	apiv1.RegisterTestServiceServer(srv, &benchTestService{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}

	go func() { _ = srv.Serve(lis) }()

	return lis.Addr().String(), srv.Stop
}

// mtlsServer creates an mTLS gRPC server.
func mtlsServer(b *testing.B, ca *benchCA) (string, func()) {
	b.Helper()

	serverCert, err := ca.issueCert("bench-server", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatalf("issue server cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	logger := zap.NewNop()
	mtlsCfg := mtls.Config{}

	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainUnaryInterceptor(mtls.UnaryInterceptor(mtlsCfg, logger)),
	)
	apiv1.RegisterTestServiceServer(srv, &benchTestService{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}

	go func() { _ = srv.Serve(lis) }()

	return lis.Addr().String(), srv.Stop
}

// ---------------------------------------------------------------------------
// OIDC mock helpers
// ---------------------------------------------------------------------------

type benchTokenVerifier struct {
	token *gooidc.IDToken
}

func (v *benchTokenVerifier) Verify(_ context.Context, _ string) (*gooidc.IDToken, error) {
	return v.token, nil
}

type benchProvider struct {
	verifier authoidc.TokenVerifier
}

func (p *benchProvider) Verifier() authoidc.TokenVerifier {
	return p.verifier
}

func (p *benchProvider) Healthy(_ context.Context) bool {
	return true
}

func setIDTokenClaims(token *gooidc.IDToken, claimsJSON []byte) {
	v := reflect.ValueOf(token).Elem()
	f := v.FieldByName("claims")
	ptr := unsafe.Pointer(f.UnsafeAddr()) //nolint:gosec // test-only
	*(*[]byte)(ptr) = claimsJSON
}

// oidcServer creates a gRPC server with OIDC authentication.
func oidcServer(b *testing.B) (string, func()) {
	b.Helper()

	token := &gooidc.IDToken{
		Issuer:   "https://bench-issuer.example.com",
		Subject:  "bench-user",
		Audience: []string{"bench-client"},
	}
	setIDTokenClaims(token, []byte(`{"sub":"bench-user"}`))

	provider := &benchProvider{
		verifier: &benchTokenVerifier{token: token},
	}

	authCfg := config.AuthConfig{
		OIDCEnabled:  true,
		OIDCClientID: "bench-client",
	}

	logger := zap.NewNop()

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authoidc.UnaryInterceptor(provider, authCfg, logger)),
	)
	apiv1.RegisterTestServiceServer(srv, &benchTestService{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}

	go func() { _ = srv.Serve(lis) }()

	return lis.Addr().String(), srv.Stop
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

func insecureClient(b *testing.B, address string) (*grpc.ClientConn, apiv1.TestServiceClient) {
	b.Helper()

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}

	return conn, apiv1.NewTestServiceClient(conn)
}

func tlsClient(b *testing.B, address string, caPool *x509.CertPool) (*grpc.ClientConn, apiv1.TestServiceClient) {
	b.Helper()

	tlsConfig := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}

	return conn, apiv1.NewTestServiceClient(conn)
}

func mtlsClient(b *testing.B, address string, clientCert tls.Certificate, caPool *x509.CertPool) (*grpc.ClientConn, apiv1.TestServiceClient) {
	b.Helper()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}

	return conn, apiv1.NewTestServiceClient(conn)
}

// contextWithBearerToken creates a context with a bearer token.
func contextWithBearerToken(ctx context.Context, token string) context.Context {
	md := metadata.New(map[string]string{
		"authorization": fmt.Sprintf("Bearer %s", token),
	})
	return metadata.NewOutgoingContext(ctx, md)
}
