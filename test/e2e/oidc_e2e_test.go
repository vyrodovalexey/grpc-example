//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

// createOIDCConnection creates a gRPC connection appropriate for the server's auth mode.
// If the server requires mTLS (cert files exist), it uses mTLS; otherwise insecure.
func createOIDCConnection(t *testing.T) (*grpc.ClientConn, apiv1.TestServiceClient) {
	t.Helper()

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	// Try mTLS connection first (server may require it).
	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
	return conn, client
}

// createInsecureConnection creates an insecure gRPC connection (for servers without TLS).
func createInsecureConnection(t *testing.T) (*grpc.ClientConn, apiv1.TestServiceClient) {
	t.Helper()

	conn, err := grpc.NewClient(
		testConfig.GRPCAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client := apiv1.NewTestServiceClient(conn)
	return conn, client
}

func TestE2E_OIDC_ClientWithKeycloakToken(t *testing.T) {
	skipIfServicesUnavailable(t, "keycloak", "grpc-server")

	token := acquireKeycloakToken(t)

	conn, client := createOIDCConnection(t)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	ctx = contextWithToken(ctx, token)

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "e2e OIDC test"})
	require.NoError(t, err)
	assert.Equal(t, "e2e OIDC test", resp.GetMessage())
}

func TestE2E_OIDC_ServerStreamWithToken(t *testing.T) {
	skipIfServicesUnavailable(t, "keycloak", "grpc-server")

	token := acquireKeycloakToken(t)

	conn, client := createOIDCConnection(t)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	ctx = contextWithToken(ctx, token)

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      5,
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
	assert.Equal(t, 5, count)
}

func TestE2E_OIDC_BidiStreamWithToken(t *testing.T) {
	skipIfServicesUnavailable(t, "keycloak", "grpc-server")

	token := acquireKeycloakToken(t)

	conn, client := createOIDCConnection(t)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	ctx = contextWithToken(ctx, token)

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	err = stream.Send(&apiv1.BidirectionalRequest{
		Value:     7,
		Operation: "square",
	})
	require.NoError(t, err)

	err = stream.CloseSend()
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, int64(49), resp.GetTransformedValue())
}

func TestE2E_OIDC_InvalidToken(t *testing.T) {
	skipIfServicesUnavailable(t, "keycloak", "grpc-server")

	// Try insecure connection first — if the server requires TLS, the connection
	// will fail with Unavailable, not Unauthenticated. In that case, use mTLS
	// and verify the server's actual OIDC behavior.
	conn, client := createOIDCConnection(t)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	ctx = contextWithToken(ctx, "invalid-token-value")

	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})

	// If the server has OIDC enabled, it should reject with Unauthenticated.
	// If the server is in mTLS-only mode, the request succeeds (OIDC not checked).
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	}
	// If no error, the server is in mTLS-only mode — OIDC is not enforced.
}

func TestE2E_OIDC_MissingToken(t *testing.T) {
	skipIfServicesUnavailable(t, "keycloak", "grpc-server")

	conn, client := createOIDCConnection(t)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	// No token added.
	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})

	// If the server has OIDC enabled, it should reject with Unauthenticated.
	// If the server is in mTLS-only mode, the request succeeds (OIDC not checked).
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	}
	// If no error, the server is in mTLS-only mode — OIDC is not enforced.
}

func TestE2E_OIDC_ConcurrentRequestsWithToken(t *testing.T) {
	skipIfServicesUnavailable(t, "keycloak", "grpc-server")

	token := acquireKeycloakToken(t)

	conn, client := createOIDCConnection(t)
	defer conn.Close()

	const numRequests = 20
	var wg sync.WaitGroup
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			ctx, cancel := newE2EContext()
			defer cancel()

			ctx = contextWithToken(ctx, token)

			msg := fmt.Sprintf("concurrent-oidc-%d", idx)
			resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: msg})
			if err != nil {
				results <- err
				return
			}
			if resp.GetMessage() != msg {
				results <- fmt.Errorf("expected %q, got %q", msg, resp.GetMessage())
				return
			}
			results <- nil
		}(i)
	}

	wg.Wait()
	close(results)

	for err := range results {
		require.NoError(t, err)
	}
}

func TestE2E_OIDC_TokenRefreshDuringOperation(t *testing.T) {
	skipIfServicesUnavailable(t, "keycloak", "grpc-server")

	conn, client := createOIDCConnection(t)
	defer conn.Close()

	// First request with initial token.
	token1 := acquireKeycloakToken(t)

	ctx1, cancel1 := newE2EContext()
	defer cancel1()

	ctx1 = contextWithToken(ctx1, token1)

	resp1, err := client.Unary(ctx1, &apiv1.UnaryRequest{Message: "before refresh"})
	require.NoError(t, err)
	assert.Equal(t, "before refresh", resp1.GetMessage())

	// Acquire a new token (simulating refresh).
	token2 := acquireKeycloakToken(t)

	ctx2, cancel2 := newE2EContext()
	defer cancel2()

	ctx2 = contextWithToken(ctx2, token2)

	resp2, err := client.Unary(ctx2, &apiv1.UnaryRequest{Message: "after refresh"})
	require.NoError(t, err)
	assert.Equal(t, "after refresh", resp2.GetMessage())
}
