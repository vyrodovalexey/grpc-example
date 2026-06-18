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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	"github.com/vyrodovalexey/grpc-example/internal/metrics"
	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

// perfConfig holds connection/auth configuration for live-server performance
// tests. It mirrors the e2e suite conventions so the same environment variables
// drive both suites.
type perfConfig struct {
	GRPCAddress   string
	CertDir       string
	KeycloakURL   string
	KeycloakRealm string
	ClientID      string
	ClientSecret  string
	// AuthMode mirrors the server's AUTH_MODE (none|tls|mtls|oidc|both). When the
	// server enforces OIDC ("oidc"/"both") live clients must also present a valid
	// bearer token; when it enforces mTLS ("mtls"/"both") they must present a
	// client certificate from CertDir.
	AuthMode string
}

// liveCfg is the resolved live-server configuration, populated in TestMain.
var liveCfg *perfConfig

// TestMain is the entry point for performance tests.
func TestMain(m *testing.M) {
	liveCfg = loadPerfConfig()
	os.Exit(m.Run())
}

// loadPerfConfig loads live-server configuration from environment variables,
// falling back to the docker-compose defaults used by the e2e suite.
func loadPerfConfig() *perfConfig {
	return &perfConfig{
		GRPCAddress:   getEnvOrDefault("GRPC_ADDRESS", "127.0.0.1:50051"),
		CertDir:       getEnvOrDefault("CERT_DIR", "/tmp/grpc-test-certs"),
		KeycloakURL:   getEnvOrDefault("KEYCLOAK_URL", "http://127.0.0.1:8090"),
		KeycloakRealm: getEnvOrDefault("KC_REALM", "grpc-test"),
		ClientID:      getEnvOrDefault("KC_CLIENT_ID", "grpc-server"),
		ClientSecret:  getEnvOrDefault("KC_CLIENT_SECRET", "grpc-server-secret"),
		AuthMode:      getEnvOrDefault("AUTH_MODE", "both"),
	}
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

// mtlsEnforced reports whether the server requires a client certificate.
func mtlsEnforced() bool {
	switch liveCfg.AuthMode {
	case "mtls", "both":
		return true
	default:
		return false
	}
}

// oidcEnforced reports whether the server requires an OIDC bearer token.
func oidcEnforced() bool {
	switch liveCfg.AuthMode {
	case "oidc", "both":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Live-server prerequisite checks (graceful skip)
// ---------------------------------------------------------------------------

// skipIfCertsUnavailable skips when the configured client certificate material
// is not present on disk (required for mtls/both modes).
func skipIfCertsUnavailable(t *testing.T) {
	t.Helper()
	if !mtlsEnforced() {
		return
	}
	for _, name := range []string{"ca-cert.pem", "client-cert.pem", "client-key.pem"} {
		p := filepath.Join(liveCfg.CertDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Skipf("skipping: required cert %q not available: %v", p, err)
		}
	}
}

// skipIfKeycloakUnavailable skips when Keycloak's OIDC discovery endpoint is not
// reachable (required for oidc/both modes).
func skipIfKeycloakUnavailable(t *testing.T) {
	t.Helper()
	if !oidcEnforced() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration",
		liveCfg.KeycloakURL, liveCfg.KeycloakRealm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, http.NoBody)
	if err != nil {
		t.Skipf("skipping: cannot create Keycloak discovery request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("skipping: Keycloak not available at %s: %v", liveCfg.KeycloakURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("skipping: Keycloak discovery returned %d", resp.StatusCode)
	}
}

// skipIfLiveServerUnavailable skips when the live gRPC server cannot be reached
// over TCP within a short dial timeout.
func skipIfLiveServerUnavailable(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", liveCfg.GRPCAddress, 3*time.Second)
	if err != nil {
		t.Skipf("skipping: gRPC server not reachable at %s: %v", liveCfg.GRPCAddress, err)
	}
	_ = conn.Close()
}

// skipUnlessLivePrereqs performs all prerequisite checks for live-server tests
// given the configured AUTH_MODE.
func skipUnlessLivePrereqs(t *testing.T) {
	t.Helper()
	skipIfLiveServerUnavailable(t)
	skipIfCertsUnavailable(t)
	skipIfKeycloakUnavailable(t)
}

// ---------------------------------------------------------------------------
// Live-server token + client helpers
// ---------------------------------------------------------------------------

// acquireKeycloakToken obtains an access token from Keycloak via the
// client_credentials grant, matching the e2e suite behaviour.
func acquireKeycloakToken(t testing.TB) (string, error) {
	t.Helper()

	tokenURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/token",
		liveCfg.KeycloakURL, liveCfg.KeycloakRealm,
	)
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {liveCfg.ClientID},
		"client_secret": {liveCfg.ClientSecret},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed (%d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	return tokenResp.AccessToken, nil
}

// liveClient dials the live gRPC server using the credentials appropriate for
// the configured AUTH_MODE (mTLS client cert for mtls/both, insecure otherwise).
func liveClient(t testing.TB) (*grpc.ClientConn, apiv1.TestServiceClient, error) {
	t.Helper()

	if mtlsEnforced() {
		certFile := filepath.Join(liveCfg.CertDir, "client-cert.pem")
		keyFile := filepath.Join(liveCfg.CertDir, "client-key.pem")
		caFile := filepath.Join(liveCfg.CertDir, "ca-cert.pem")

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load client keypair: %w", err)
		}
		caPEM, err := os.ReadFile(caFile) //nolint:gosec // test cert path from env
		if err != nil {
			return nil, nil, fmt.Errorf("read CA: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, nil, fmt.Errorf("append CA cert failed")
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
			MinVersion:   tls.VersionTLS12,
		}
		conn, err := grpc.NewClient(liveCfg.GRPCAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		if err != nil {
			return nil, nil, err
		}
		return conn, apiv1.NewTestServiceClient(conn), nil
	}

	conn, err := grpc.NewClient(liveCfg.GRPCAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return conn, apiv1.NewTestServiceClient(conn), nil
}

// liveAuthContext returns a context carrying a freshly acquired bearer token
// when the server enforces OIDC; otherwise it returns ctx unchanged.
func liveAuthContext(t testing.TB, ctx context.Context) (context.Context, error) {
	t.Helper()
	if !oidcEnforced() {
		return ctx, nil
	}
	token, err := acquireKeycloakToken(t)
	if err != nil {
		return ctx, err
	}
	return contextWithBearerToken(ctx, token), nil
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

// bothServer creates a gRPC server enforcing BOTH mTLS (client cert) AND OIDC
// (bearer token), modelling the live server's AUTH_MODE=both.
func bothServer(b *testing.B, ca *benchCA) (string, func()) {
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

	token := &gooidc.IDToken{
		Issuer:   "https://bench-issuer.example.com",
		Subject:  "bench-user",
		Audience: []string{"bench-client"},
	}
	setIDTokenClaims(token, []byte(`{"sub":"bench-user"}`))
	provider := &benchProvider{verifier: &benchTokenVerifier{token: token}}

	authCfg := config.AuthConfig{
		OIDCEnabled:  true,
		OIDCClientID: "bench-client",
	}
	logger := zap.NewNop()

	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainUnaryInterceptor(
			mtls.UnaryInterceptor(mtls.Config{}, logger),
			authoidc.UnaryInterceptor(provider, authCfg, logger),
		),
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
// Streaming service for stream-metrics benchmarks
// ---------------------------------------------------------------------------

// benchStreamService streams `Count` responses with no delay so streaming
// throughput/metrics overhead can be measured deterministically.
type benchStreamService struct {
	apiv1.UnimplementedTestServiceServer
}

func (s *benchStreamService) Unary(_ context.Context, req *apiv1.UnaryRequest) (*apiv1.UnaryResponse, error) {
	return &apiv1.UnaryResponse{Message: req.GetMessage(), Timestamp: time.Now().UnixNano()}, nil
}

func (s *benchStreamService) ServerStream(req *apiv1.StreamRequest, stream apiv1.TestService_ServerStreamServer) error {
	count := req.GetCount()
	for i := int32(0); i < count; i++ {
		if err := stream.Send(&apiv1.StreamResponse{Sequence: i + 1, Timestamp: time.Now().UnixNano()}); err != nil {
			return err
		}
	}
	return nil
}

// streamServer creates an insecure gRPC server with the streaming service and an
// optional metrics stream interceptor.
func streamServer(b *testing.B, withMetrics bool) (string, func()) {
	b.Helper()

	var opts []grpc.ServerOption
	if withMetrics {
		opts = append(opts, grpc.ChainStreamInterceptor(metrics.StreamServerInterceptor()))
	}
	srv := grpc.NewServer(opts...)
	apiv1.RegisterTestServiceServer(srv, &benchStreamService{})

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
