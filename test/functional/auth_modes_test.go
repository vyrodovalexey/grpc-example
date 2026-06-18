//go:build functional

package functional

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
	authoidc "github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

// TestFunctional_AuthModes_InsecureMode tests backward compatibility with no auth.
func TestFunctional_AuthModes_InsecureMode(t *testing.T) {
	t.Parallel()

	// The default suite runs in insecure mode.
	client := getClient()

	ctx, cancel := newTestContext()
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "insecure mode"})
	require.NoError(t, err)
	assert.Equal(t, "insecure mode", resp.GetMessage())
}

// TestFunctional_AuthModes_TLSOnly tests TLS-only mode (no client auth).
func TestFunctional_AuthModes_TLSOnly(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("TLS-Only CA")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	// Server with TLS but no client auth requirement.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	testService := newTestService(zap.NewNop())
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	// Client connects with TLS but no client cert.
	clientTLSConfig := &tls.Config{
		RootCAs:    ca.pool,
		MinVersion: tls.VersionTLS12,
	}
	clientCreds := credentials.NewTLS(clientTLSConfig)

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(clientCreds))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	ctx, cancel := newTestContext()
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "TLS only"})
	require.NoError(t, err)
	assert.Equal(t, "TLS only", resp.GetMessage())
}

// TestFunctional_AuthModes_MTLSMode tests mTLS authentication mode.
func TestFunctional_AuthModes_MTLSMode(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("mTLS Mode CA")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	env, err := setupMTLSServer(ca, serverCert, mtls.Config{}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(env.teardown)

	clientCert, err := ca.issueClientCert("mtls-mode-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "mTLS mode"})
	require.NoError(t, err)
	assert.Equal(t, "mTLS mode", resp.GetMessage())
}

// TestFunctional_AuthModes_OIDCMode tests OIDC authentication mode.
func TestFunctional_AuthModes_OIDCMode(t *testing.T) {
	t.Parallel()

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s","iss":"%s"}`, testSubject, testIssuer),
	)
	verifier := &mockTokenVerifier{token: token}
	env := setupDefaultOIDCEnv(t, verifier, testAudience)

	conn, client, err := createOIDCClient(env.address, "valid-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "valid-token")

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "OIDC mode"})
	require.NoError(t, err)
	assert.Equal(t, "OIDC mode", resp.GetMessage())
}

// TestFunctional_AuthModes_CombinedMTLSAndOIDC tests combined mTLS + OIDC mode.
func TestFunctional_AuthModes_CombinedMTLSAndOIDC(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("Combined Auth CA")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	// Create OIDC mock.
	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s","iss":"%s"}`, testSubject, testIssuer),
	)
	verifier := &mockTokenVerifier{token: token}
	provider := &mockProvider{verifier: verifier}
	authCfg := config.AuthConfig{
		OIDCEnabled:  true,
		OIDCClientID: testClientID,
		OIDCAudience: testAudience,
	}

	// Server with both mTLS and OIDC interceptors.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	logger := zap.NewNop()
	mtlsCfg := mtls.Config{}

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			mtls.UnaryInterceptor(mtlsCfg, logger),
			authoidc.UnaryInterceptor(provider, authCfg, logger),
		),
		grpc.ChainStreamInterceptor(
			mtls.StreamInterceptor(mtlsCfg, logger),
			authoidc.StreamInterceptor(provider, authCfg, logger),
		),
	)

	testService := newTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	// Client with both mTLS cert and OIDC token.
	clientCert, err := ca.issueClientCert("combined-client")
	require.NoError(t, err)

	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.pool,
		MinVersion:   tls.VersionTLS12,
	}
	clientCreds := credentials.NewTLS(clientTLSConfig)

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(clientCreds))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "valid-token")

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "combined auth"})
	require.NoError(t, err)
	assert.Equal(t, "combined auth", resp.GetMessage())
}

// TestFunctional_AuthModes_CombinedMTLSAndOIDC_MissingToken tests combined mode with missing OIDC token.
func TestFunctional_AuthModes_CombinedMTLSAndOIDC_MissingToken(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("Combined Auth CA 2")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	verifier := &mockTokenVerifier{token: token}
	provider := &mockProvider{verifier: verifier}
	authCfg := config.AuthConfig{
		OIDCEnabled:  true,
		OIDCClientID: testClientID,
		OIDCAudience: testAudience,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	logger := zap.NewNop()
	mtlsCfg := mtls.Config{}

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			mtls.UnaryInterceptor(mtlsCfg, logger),
			authoidc.UnaryInterceptor(provider, authCfg, logger),
		),
	)

	testService := newTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	// Client with mTLS cert but NO OIDC token.
	clientCert, err := ca.issueClientCert("combined-no-token-client")
	require.NoError(t, err)

	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.pool,
		MinVersion:   tls.VersionTLS12,
	}
	clientCreds := credentials.NewTLS(clientTLSConfig)

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(clientCreds))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	ctx, cancel := newTestContext()
	defer cancel()

	// No bearer token added — OIDC interceptor should reject.
	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

// TestFunctional_AuthModes_InsecureToTLSUpgrade tests that insecure client cannot connect to TLS server.
func TestFunctional_AuthModes_InsecureToTLSUpgrade(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("Upgrade CA")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	testService := newTestService(zap.NewNop())
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	// Try to connect with insecure credentials to a TLS server.
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	ctx, cancel := newTestContext()
	defer cancel()

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

// TestFunctional_AuthModes_TableDriven tests different auth mode configurations.
func TestFunctional_AuthModes_TableDriven(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		mode    authMode
		wantErr bool
	}{
		{
			name:    "insecure_mode_works",
			mode:    authModeInsecure,
			wantErr: false,
		},
		{
			name:    "tls_mode_works",
			mode:    authModeTLS,
			wantErr: false,
		},
		{
			name:    "mtls_mode_works",
			mode:    authModeMTLS,
			wantErr: false,
		},
		{
			name:    "oidc_mode_works",
			mode:    authModeOIDC,
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := newTestContext()
			defer cancel()

			switch tc.mode {
			case authModeInsecure:
				client := getClient()
				resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "insecure"})
				if tc.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					assert.Equal(t, "insecure", resp.GetMessage())
				}

			case authModeTLS:
				ca, err := newTestCA("Table TLS CA")
				require.NoError(t, err)

				serverCert, err := ca.issueServerCert()
				require.NoError(t, err)

				tlsCfg := &tls.Config{
					Certificates: []tls.Certificate{serverCert},
					ClientAuth:   tls.NoClientCert,
					MinVersion:   tls.VersionTLS12,
				}
				creds := credentials.NewTLS(tlsCfg)
				srv := grpc.NewServer(grpc.Creds(creds))
				svc := newTestService(zap.NewNop())
				apiv1.RegisterTestServiceServer(srv, svc)

				lis, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				go func() { _ = srv.Serve(lis) }()
				t.Cleanup(srv.Stop)

				conn, client, err := createInsecureTLSClient(lis.Addr().String(), ca.pool)
				require.NoError(t, err)
				defer conn.Close()

				resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "tls"})
				require.NoError(t, err)
				assert.Equal(t, "tls", resp.GetMessage())

			case authModeMTLS:
				ca, err := newTestCA("Table mTLS CA")
				require.NoError(t, err)

				serverCert, err := ca.issueServerCert()
				require.NoError(t, err)

				env, err := setupMTLSServer(ca, serverCert, mtls.Config{}, zap.NewNop())
				require.NoError(t, err)
				t.Cleanup(env.teardown)

				clientCert, err := ca.issueClientCert("table-mtls-client")
				require.NoError(t, err)

				conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
				require.NoError(t, err)
				defer conn.Close()

				resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "mtls"})
				require.NoError(t, err)
				assert.Equal(t, "mtls", resp.GetMessage())

			case authModeOIDC:
				token := createIDTokenWithClaims(
					testIssuer, testSubject, []string{testAudience},
					fmt.Sprintf(`{"sub":"%s"}`, testSubject),
				)
				verifier := &mockTokenVerifier{token: token}
				env := setupDefaultOIDCEnv(t, verifier, testAudience)

				conn, client, err := createOIDCClient(env.address, "valid-token")
				require.NoError(t, err)
				defer conn.Close()

				oidcCtx := contextWithBearerToken(ctx, "valid-token")
				resp, err := client.Unary(oidcCtx, &apiv1.UnaryRequest{Message: "oidc"})
				require.NoError(t, err)
				assert.Equal(t, "oidc", resp.GetMessage())
			}
		})
	}
}

// TestFunctional_AuthModes_CombinedMTLSAndOIDC_MissingCert verifies that in
// combined (both) mode an OIDC token without a client certificate fails the TLS
// handshake with Unavailable.
func TestFunctional_AuthModes_CombinedMTLSAndOIDC_MissingCert(t *testing.T) {
	t.Parallel()

	env := setupBothAuthServer(t)

	// Connect with an insecure (no-TLS) client: handshake against the mTLS
	// server fails before any RPC reaches the OIDC interceptor.
	conn, err := grpc.NewClient(env.address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	ctx, cancel := newTestContext()
	defer cancel()
	ctx = contextWithBearerToken(ctx, "valid")

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

// dialForMode returns a connected client and a per-request context preparer for
// the given auth mode. The cleanup is registered via t.Cleanup.
func dialForMode(t *testing.T, mode string) (apiv1.TestServiceClient, func(context.Context) context.Context) {
	t.Helper()

	switch mode {
	case config.AuthModeNone:
		conn, err := grpc.NewClient(getAddress(),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return apiv1.NewTestServiceClient(conn), func(ctx context.Context) context.Context { return ctx }

	case config.AuthModeMTLS:
		env, ca := setupDefaultMTLSEnv(t)
		clientCert, err := ca.issueClientCert("allmodes-mtls")
		require.NoError(t, err)
		conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return client, func(ctx context.Context) context.Context { return ctx }

	case config.AuthModeOIDC:
		token := createIDTokenWithClaims(
			testIssuer, testSubject, []string{testAudience},
			fmt.Sprintf(`{"sub":"%s"}`, testSubject),
		)
		env := setupDefaultOIDCEnv(t, &mockTokenVerifier{token: token}, testAudience)
		conn, client, err := createOIDCClient(env.address, "valid")
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return client, func(ctx context.Context) context.Context {
			return contextWithBearerToken(ctx, "valid")
		}

	case config.AuthModeBoth:
		env := setupBothAuthServer(t)
		conn, client := env.dialValid(t)
		t.Cleanup(func() { _ = conn.Close() })
		return client, func(ctx context.Context) context.Context {
			return contextWithBearerToken(ctx, "valid")
		}

	default:
		t.Fatalf("unknown auth mode %q", mode)
		return nil, nil
	}
}

// allAuthModes is the set of modes exercised by the AllModes_* tests.
var allAuthModes = []string{
	config.AuthModeNone,
	config.AuthModeMTLS,
	config.AuthModeOIDC,
	config.AuthModeBoth,
}

// TestFunctional_AuthModes_AllModes_Unary verifies the unary happy path under
// none/mtls/oidc/both.
func TestFunctional_AuthModes_AllModes_Unary(t *testing.T) {
	t.Parallel()

	for _, mode := range allAuthModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			client, prep := dialForMode(t, mode)

			ctx, cancel := newTestContext()
			defer cancel()
			ctx = prep(ctx)

			resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "unary-" + mode})
			require.NoError(t, err)
			assert.Equal(t, "unary-"+mode, resp.GetMessage())
		})
	}
}

// TestFunctional_AuthModes_AllModes_ServerStream verifies the server-stream happy
// path under none/mtls/oidc/both.
func TestFunctional_AuthModes_AllModes_ServerStream(t *testing.T) {
	t.Parallel()

	for _, mode := range allAuthModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			client, prep := dialForMode(t, mode)

			ctx, cancel := newTestContext()
			defer cancel()
			ctx = prep(ctx)

			stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{Count: 3, IntervalMs: 10})
			require.NoError(t, err)

			count := 0
			for {
				_, recvErr := stream.Recv()
				if recvErr == io.EOF {
					break
				}
				require.NoError(t, recvErr)
				count++
			}
			assert.Equal(t, 3, count)
		})
	}
}

// TestFunctional_AuthModes_AllModes_BidiStream verifies the bidi-stream happy path
// under none/mtls/oidc/both.
func TestFunctional_AuthModes_AllModes_BidiStream(t *testing.T) {
	t.Parallel()

	for _, mode := range allAuthModes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			client, prep := dialForMode(t, mode)

			ctx, cancel := newTestContext()
			defer cancel()
			ctx = prep(ctx)

			stream, err := client.BidirectionalStream(ctx)
			require.NoError(t, err)

			require.NoError(t, stream.Send(&apiv1.BidirectionalRequest{Value: 21, Operation: "double"}))
			require.NoError(t, stream.CloseSend())

			resp, err := stream.Recv()
			require.NoError(t, err)
			assert.Equal(t, int64(42), resp.GetTransformedValue())
		})
	}
}
