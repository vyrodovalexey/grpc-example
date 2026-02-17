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

	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

func TestE2E_MTLS_ClientWithVaultIssuedCert(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "grpc-server")

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "e2e mTLS test"})
	require.NoError(t, err)
	assert.Equal(t, "e2e mTLS test", resp.GetMessage())
	assert.Greater(t, resp.GetTimestamp(), int64(0))
}

func TestE2E_MTLS_ServerStreamWithVaultCert(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "grpc-server")

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

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

func TestE2E_MTLS_BidiStreamWithVaultCert(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "grpc-server")

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	// Send values.
	for i := int64(1); i <= 3; i++ {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     i,
			Operation: "double",
		})
		require.NoError(t, err)
	}

	err = stream.CloseSend()
	require.NoError(t, err)

	// Receive responses.
	var responses []*apiv1.BidirectionalResponse
	for {
		resp, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		require.NoError(t, recvErr)
		responses = append(responses, resp)
	}

	assert.Len(t, responses, 3)
	for i, resp := range responses {
		assert.Equal(t, int64(i+1), resp.GetOriginalValue())
		assert.Equal(t, int64((i+1)*2), resp.GetTransformedValue())
	}
}

func TestE2E_MTLS_MultipleClientsWithDifferentCerts(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "grpc-server")

	certDir := testConfig.CertDir
	caFile := filepath.Join(certDir, "ca-cert.pem")

	// Try to use multiple client cert files if available.
	clientCerts := []struct {
		certFile string
		keyFile  string
		name     string
	}{
		{
			certFile: filepath.Join(certDir, "client-cert.pem"),
			keyFile:  filepath.Join(certDir, "client-key.pem"),
			name:     "client-1",
		},
	}

	var wg sync.WaitGroup
	errors := make(chan error, len(clientCerts))

	for _, cc := range clientCerts {
		wg.Add(1)
		go func(certFile, keyFile, name string) {
			defer wg.Done()

			conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
			defer conn.Close()

			ctx, cancel := newE2EContext()
			defer cancel()

			resp, err := client.Unary(ctx, &apiv1.UnaryRequest{
				Message: fmt.Sprintf("from %s", name),
			})
			if err != nil {
				errors <- fmt.Errorf("client %s failed: %w", name, err)
				return
			}
			if resp.GetMessage() != fmt.Sprintf("from %s", name) {
				errors <- fmt.Errorf("client %s: unexpected response: %s", name, resp.GetMessage())
				return
			}
			errors <- nil
		}(cc.certFile, cc.keyFile, cc.name)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		require.NoError(t, err)
	}
}

func TestE2E_MTLS_ConcurrentRequests(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "grpc-server")

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
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

			msg := fmt.Sprintf("concurrent-%d", idx)
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
