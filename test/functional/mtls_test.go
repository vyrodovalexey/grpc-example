//go:build functional

package functional

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

// setupDefaultMTLSEnv creates a default mTLS test environment with no subject restrictions.
func setupDefaultMTLSEnv(t *testing.T) (*mtlsTestEnv, *testCA) {
	t.Helper()

	ca, err := newTestCA("Test CA")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	env, err := setupMTLSServer(ca, serverCert, mtls.Config{}, zap.NewNop())
	require.NoError(t, err)

	t.Cleanup(env.teardown)
	return env, ca
}

func TestFunctional_MTLS_ValidClientCertificate(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	clientCert, err := ca.issueClientCert("valid-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "mTLS test"})
	require.NoError(t, err)
	assert.Equal(t, "mTLS test", resp.GetMessage())
	assert.Greater(t, resp.GetTimestamp(), int64(0))
}

func TestFunctional_MTLS_InvalidClientCertificate(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	// Create a different CA and issue a client cert from it.
	wrongCA, err := newTestCA("Wrong CA")
	require.NoError(t, err)

	wrongCert, err := wrongCA.issueClientCert("wrong-ca-client")
	require.NoError(t, err)

	// Client uses the wrong cert but trusts the correct server CA.
	conn, client, err := createMTLSClient(env.address, wrongCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestFunctional_MTLS_ExpiredClientCertificate(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	expiredCert, err := ca.issueExpiredClientCert("expired-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, expiredCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestFunctional_MTLS_WrongCASignedCertificate(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	// Create a completely separate CA.
	otherCA, err := newTestCA("Other CA")
	require.NoError(t, err)

	otherCert, err := otherCA.issueClientCert("other-ca-client")
	require.NoError(t, err)

	// Client uses cert from other CA but trusts the correct server CA.
	conn, client, err := createMTLSClient(env.address, otherCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestFunctional_MTLS_MissingClientCertificate(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	// Connect without a client certificate.
	conn, client, err := createInsecureTLSClient(env.address, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestFunctional_MTLS_CertificateWithWrongSubject(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("Test CA")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	// Server restricts to specific subjects.
	restrictedCfg := mtls.Config{
		AllowedSubjects: []string{"allowed-client"},
	}

	env, err := setupMTLSServer(ca, serverCert, restrictedCfg, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(env.teardown)

	// Issue a cert with a different CN.
	wrongSubjectCert, err := ca.issueClientCert("wrong-subject-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, wrongSubjectCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "not in allowed subjects")
}

func TestFunctional_MTLS_CertificateWithAllowedSubject(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("Test CA")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	restrictedCfg := mtls.Config{
		AllowedSubjects: []string{"allowed-client"},
	}

	env, err := setupMTLSServer(ca, serverCert, restrictedCfg, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(env.teardown)

	// Issue a cert with the allowed CN.
	allowedCert, err := ca.issueClientCert("allowed-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, allowedCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "allowed"})
	require.NoError(t, err)
	assert.Equal(t, "allowed", resp.GetMessage())
}

func TestFunctional_MTLS_AllGRPCMethods_Unary(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	clientCert, err := ca.issueClientCert("method-test-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "unary with mTLS"})
	require.NoError(t, err)
	assert.Equal(t, "unary with mTLS", resp.GetMessage())
}

func TestFunctional_MTLS_AllGRPCMethods_ServerStream(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	clientCert, err := ca.issueClientCert("stream-test-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      3,
		IntervalMs: 10,
	})
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
}

func TestFunctional_MTLS_AllGRPCMethods_BidiStream(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	clientCert, err := ca.issueClientCert("bidi-test-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	err = stream.Send(&apiv1.BidirectionalRequest{
		Value:     42,
		Operation: "double",
	})
	require.NoError(t, err)

	err = stream.CloseSend()
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, int64(84), resp.GetTransformedValue())
}

func TestFunctional_MTLS_MultipleClientsWithDifferentCerts(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	// Create multiple clients with different certificates.
	clients := make([]struct {
		conn   *grpc.ClientConn
		client apiv1.TestServiceClient
		name   string
	}, 3)

	for i := range clients {
		cn := "client-" + string(rune('A'+i))
		cert, err := ca.issueClientCert(cn)
		require.NoError(t, err)

		conn, client, err := createMTLSClient(env.address, cert, ca.pool)
		require.NoError(t, err)

		clients[i].conn = conn
		clients[i].client = client
		clients[i].name = cn
	}

	defer func() {
		for _, c := range clients {
			c.conn.Close()
		}
	}()

	// All clients should be able to make requests.
	for _, c := range clients {
		ctx, cancel := newTestContext()
		resp, err := c.client.Unary(ctx, &apiv1.UnaryRequest{Message: "from " + c.name})
		cancel()

		require.NoError(t, err)
		assert.Equal(t, "from "+c.name, resp.GetMessage())
	}
}

func TestFunctional_MTLS_TableDriven(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("Test CA")
	require.NoError(t, err)

	wrongCA, err := newTestCA("Wrong CA")
	require.NoError(t, err)

	serverCert, err := ca.issueServerCert()
	require.NoError(t, err)

	validCert, err := ca.issueClientCert("valid-client")
	require.NoError(t, err)

	expiredCert, err := ca.issueExpiredClientCert("expired-client")
	require.NoError(t, err)

	wrongCACert, err := wrongCA.issueClientCert("wrong-ca-client")
	require.NoError(t, err)

	env, err := setupMTLSServer(ca, serverCert, mtls.Config{}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(env.teardown)

	testCases := []struct {
		name      string
		setupConn func(t *testing.T) (*grpc.ClientConn, apiv1.TestServiceClient)
		wantErr   bool
		errCode   codes.Code
	}{
		{
			name: "valid_certificate",
			setupConn: func(t *testing.T) (*grpc.ClientConn, apiv1.TestServiceClient) {
				conn, client, err := createMTLSClient(env.address, validCert, ca.pool)
				require.NoError(t, err)
				return conn, client
			},
			wantErr: false,
		},
		{
			name: "expired_certificate",
			setupConn: func(t *testing.T) (*grpc.ClientConn, apiv1.TestServiceClient) {
				conn, client, err := createMTLSClient(env.address, expiredCert, ca.pool)
				require.NoError(t, err)
				return conn, client
			},
			wantErr: true,
			errCode: codes.Unavailable,
		},
		{
			name: "wrong_ca_certificate",
			setupConn: func(t *testing.T) (*grpc.ClientConn, apiv1.TestServiceClient) {
				conn, client, err := createMTLSClient(env.address, wrongCACert, ca.pool)
				require.NoError(t, err)
				return conn, client
			},
			wantErr: true,
			errCode: codes.Unavailable,
		},
		{
			name: "no_client_certificate",
			setupConn: func(t *testing.T) (*grpc.ClientConn, apiv1.TestServiceClient) {
				conn, client, err := createInsecureTLSClient(env.address, ca.pool)
				require.NoError(t, err)
				return conn, client
			},
			wantErr: true,
			errCode: codes.Unavailable,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn, client := tc.setupConn(t)
			defer conn.Close()

			ctx, cancel := newTestContext()
			defer cancel()

			resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "test"})

			if tc.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tc.errCode, st.Code())
			} else {
				require.NoError(t, err)
				assert.Equal(t, "test", resp.GetMessage())
			}
		})
	}
}

func TestFunctional_MTLS_FutureClientCertificate(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	// Issue a certificate that is not yet valid.
	futureCert, err := ca.issueCert(
		"future-client",
		nil,
		nil,
		time.Now().Add(24*time.Hour),
		time.Now().Add(48*time.Hour),
	)
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, futureCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestFunctional_MTLS_SelfSignedClientCertificate(t *testing.T) {
	t.Parallel()

	env, ca := setupDefaultMTLSEnv(t)

	// Create a self-signed certificate (not signed by the server's CA).
	selfCA, err := newTestCA("Self-Signed")
	require.NoError(t, err)

	selfCert, err := selfCA.issueClientCert("self-signed-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, selfCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestFunctional_MTLS_ServerWithIPSAN(t *testing.T) {
	t.Parallel()

	ca, err := newTestCA("Test CA")
	require.NoError(t, err)

	// Issue server cert with IP SAN for 127.0.0.1.
	serverCert, err := ca.issueCert(
		"test-server",
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)
	require.NoError(t, err)

	env, err := setupMTLSServer(ca, serverCert, mtls.Config{}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(env.teardown)

	clientCert, err := ca.issueClientCert("ip-san-client")
	require.NoError(t, err)

	conn, client, err := createMTLSClient(env.address, clientCert, ca.pool)
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "IP SAN test"})
	require.NoError(t, err)
	assert.Equal(t, "IP SAN test", resp.GetMessage())
}
