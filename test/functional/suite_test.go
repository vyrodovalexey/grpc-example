//go:build functional

// Package functional provides functional tests for the gRPC test server.
package functional

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

const (
	// testTimeout is the default timeout for test operations.
	testTimeout = 30 * time.Second

	// serverStartTimeout is the timeout for server startup.
	serverStartTimeout = 5 * time.Second
)

// authMode defines the authentication mode for the test suite.
type authMode string

const (
	authModeInsecure authMode = "insecure"
	authModeTLS      authMode = "tls"
	authModeMTLS     authMode = "mtls"
	authModeOIDC     authMode = "oidc"
)

// testSuite holds the test infrastructure.
type testSuite struct {
	server     *grpc.Server
	client     apiv1.TestServiceClient
	conn       *grpc.ClientConn
	address    string
	cancelFunc context.CancelFunc
}

var suite *testSuite

// TestMain sets up and tears down the test infrastructure.
func TestMain(m *testing.M) {
	var err error
	suite, err = setupTestSuite()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup test suite: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	suite.teardown()
	os.Exit(code)
}

// setupTestSuite creates a new test suite with a running gRPC server.
func setupTestSuite() (*testSuite, error) {
	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %w", err)
	}
	address := listener.Addr().String()

	// Create logger (silent for tests)
	logger := zap.NewNop()

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register test service
	testService := newTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	serverErrCh := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	// Wait for server to be ready
	conn, err := waitForServer(ctx, address)
	if err != nil {
		cancel()
		grpcServer.Stop()
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	client := apiv1.NewTestServiceClient(conn)

	return &testSuite{
		server:     grpcServer,
		client:     client,
		conn:       conn,
		address:    address,
		cancelFunc: cancel,
	}, nil
}

// waitForServer waits for the gRPC server to be ready.
func waitForServer(ctx context.Context, address string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, serverStartTimeout)
	defer cancel()

	var conn *grpc.ClientConn
	var err error

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for server: %w", err)
		default:
			conn, err = grpc.NewClient(
				address,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err == nil {
				return conn, nil
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// teardown cleans up the test infrastructure.
func (s *testSuite) teardown() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.server != nil {
		s.server.GracefulStop()
	}
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
}

// getClient returns the test service client.
func getClient() apiv1.TestServiceClient {
	return suite.client
}

// getAddress returns the server address.
func getAddress() string {
	return suite.address
}

// newTestContext creates a new context with the default test timeout.
func newTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), testTimeout)
}

// ---------------------------------------------------------------------------
// TLS / mTLS helpers
// ---------------------------------------------------------------------------

// testCA holds a self-signed CA for test certificate generation.
type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	pool    *x509.CertPool
}

// newTestCA creates a new self-signed CA for testing.
func newTestCA(cn string) (*testCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		pool:    pool,
	}, nil
}

// issueCert issues a certificate signed by this CA.
func (ca *testCA) issueCert(cn string, dnsNames []string, ips []net.IP, notBefore, notAfter time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		DNSNames:    dnsNames,
		IPAddresses: ips,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshaling key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// issueServerCert issues a server certificate valid for localhost.
func (ca *testCA) issueServerCert() (tls.Certificate, error) {
	return ca.issueCert(
		"test-server",
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)
}

// issueClientCert issues a client certificate with the given CN.
func (ca *testCA) issueClientCert(cn string) (tls.Certificate, error) {
	return ca.issueCert(
		cn,
		nil,
		nil,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)
}

// issueExpiredClientCert issues an already-expired client certificate.
func (ca *testCA) issueExpiredClientCert(cn string) (tls.Certificate, error) {
	return ca.issueCert(
		cn,
		nil,
		nil,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-24*time.Hour),
	)
}

// ---------------------------------------------------------------------------
// mTLS server/client helpers
// ---------------------------------------------------------------------------

// mtlsTestEnv holds a complete mTLS test environment.
type mtlsTestEnv struct {
	ca         *testCA
	serverCert tls.Certificate
	address    string
	server     *grpc.Server
	cancelFunc context.CancelFunc
}

// setupMTLSServer creates a gRPC server with mTLS enabled.
func setupMTLSServer(ca *testCA, serverCert tls.Certificate, interceptorCfg mtls.Config, logger *zap.Logger) (*mtlsTestEnv, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(mtls.UnaryInterceptor(interceptorCfg, logger)),
		grpc.ChainStreamInterceptor(mtls.StreamInterceptor(interceptorCfg, logger)),
	)

	testService := newTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	address := listener.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = grpcServer.Serve(listener)
	}()

	// Suppress unused variable warning.
	_ = ctx

	return &mtlsTestEnv{
		ca:         ca,
		serverCert: serverCert,
		address:    address,
		server:     grpcServer,
		cancelFunc: cancel,
	}, nil
}

// teardown cleans up the mTLS test environment.
func (env *mtlsTestEnv) teardown() {
	if env.server != nil {
		env.server.Stop()
	}
	if env.cancelFunc != nil {
		env.cancelFunc()
	}
}

// createMTLSClient creates a gRPC client with the given client certificate.
func createMTLSClient(address string, clientCert tls.Certificate, caPool *x509.CertPool) (*grpc.ClientConn, apiv1.TestServiceClient, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating client: %w", err)
	}

	client := apiv1.NewTestServiceClient(conn)
	return conn, client, nil
}

// createInsecureTLSClient creates a gRPC client with TLS but no client certificate.
func createInsecureTLSClient(address string, caPool *x509.CertPool) (*grpc.ClientConn, apiv1.TestServiceClient, error) {
	tlsConfig := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating client: %w", err)
	}

	client := apiv1.NewTestServiceClient(conn)
	return conn, client, nil
}

// ---------------------------------------------------------------------------
// OIDC helpers
// ---------------------------------------------------------------------------

// mockTokenVerifier implements oidc.TokenVerifier for testing.
type mockTokenVerifier struct {
	token *gooidc.IDToken
	err   error
}

func (m *mockTokenVerifier) Verify(_ context.Context, _ string) (*gooidc.IDToken, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

// mockProvider implements oidc.Provider for testing.
type mockProvider struct {
	verifier authoidc.TokenVerifier
}

func (m *mockProvider) Verifier() authoidc.TokenVerifier {
	return m.verifier
}

// setIDTokenClaims sets the unexported claims field on an IDToken for testing.
func setIDTokenClaims(token *gooidc.IDToken, claimsJSON []byte) {
	v := reflect.ValueOf(token).Elem()
	f := v.FieldByName("claims")
	ptr := unsafe.Pointer(f.UnsafeAddr()) //nolint:gosec // test-only
	*(*[]byte)(ptr) = claimsJSON
}

// createIDTokenWithClaims creates an IDToken with claims set for testing.
func createIDTokenWithClaims(issuer, subject string, audience []string, claimsJSON string) *gooidc.IDToken {
	token := &gooidc.IDToken{
		Issuer:   issuer,
		Subject:  subject,
		Audience: audience,
	}
	setIDTokenClaims(token, []byte(claimsJSON))
	return token
}

// oidcTestEnv holds a complete OIDC test environment.
type oidcTestEnv struct {
	address    string
	server     *grpc.Server
	cancelFunc context.CancelFunc
	provider   *mockProvider
	authCfg    config.AuthConfig
}

// setupOIDCServer creates a gRPC server with OIDC authentication.
func setupOIDCServer(provider *mockProvider, authCfg config.AuthConfig, logger *zap.Logger) (*oidcTestEnv, error) {
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authoidc.UnaryInterceptor(provider, authCfg, logger)),
		grpc.ChainStreamInterceptor(authoidc.StreamInterceptor(provider, authCfg, logger)),
	)

	testService := newTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	address := listener.Addr().String()

	_, cancel := context.WithCancel(context.Background())
	go func() {
		_ = grpcServer.Serve(listener)
	}()

	return &oidcTestEnv{
		address:    address,
		server:     grpcServer,
		cancelFunc: cancel,
		provider:   provider,
		authCfg:    authCfg,
	}, nil
}

// teardown cleans up the OIDC test environment.
func (env *oidcTestEnv) teardown() {
	if env.server != nil {
		env.server.Stop()
	}
	if env.cancelFunc != nil {
		env.cancelFunc()
	}
}

// createOIDCClient creates a gRPC client that sends a bearer token.
func createOIDCClient(address, token string) (*grpc.ClientConn, apiv1.TestServiceClient, error) {
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating client: %w", err)
	}

	client := apiv1.NewTestServiceClient(conn)
	return conn, client, nil
}

// contextWithBearerToken creates a context with a bearer token in gRPC metadata.
func contextWithBearerToken(ctx context.Context, token string) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + token,
	})
	return metadata.NewOutgoingContext(ctx, md)
}
