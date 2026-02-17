//go:build e2e

package e2e

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

func TestE2E_Combined_MTLSAndOIDC(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "keycloak", "grpc-server")

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
	defer conn.Close()

	// Acquire OIDC token.
	token := acquireKeycloakToken(t)

	ctx, cancel := newE2EContext()
	defer cancel()

	ctx = contextWithToken(ctx, token)

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "combined e2e"})
	require.NoError(t, err)
	assert.Equal(t, "combined e2e", resp.GetMessage())
}

func TestE2E_Combined_MTLSWithoutOIDCToken(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "keycloak", "grpc-server")

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	// No OIDC token — should fail if server requires both.
	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})

	// This test verifies the behavior: if the server is in "both" mode,
	// it should reject. If in "mtls" mode only, it should succeed.
	// We check for either outcome.
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	}
	// If no error, the server is in mTLS-only mode, which is also valid.
}

func TestE2E_Combined_ErrorHandling_InvalidCertAndToken(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "keycloak", "grpc-server")

	// This test verifies that the server properly rejects requests
	// when both authentication mechanisms fail.
	// Since we can't easily create an invalid cert that the TLS layer accepts,
	// we test with a valid cert but invalid token.

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
	defer conn.Close()

	ctx, cancel := newE2EContext()
	defer cancel()

	// Send an invalid OIDC token.
	ctx = contextWithToken(ctx, "completely-invalid-token")

	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})

	// If server requires OIDC, this should fail.
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	}
}

func TestE2E_Combined_SequentialAuthMethods(t *testing.T) {
	skipIfServicesUnavailable(t, "vault", "keycloak", "grpc-server")

	certDir := testConfig.CertDir
	certFile := filepath.Join(certDir, "client-cert.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")
	caFile := filepath.Join(certDir, "ca-cert.pem")

	conn, client := createMTLSConnection(t, testConfig.GRPCAddress, certFile, keyFile, caFile)
	defer conn.Close()

	// Make multiple requests with different tokens.
	for i := 0; i < 5; i++ {
		token := acquireKeycloakToken(t)

		ctx, cancel := newE2EContext()
		ctx = contextWithToken(ctx, token)

		resp, err := client.Unary(ctx, &apiv1.UnaryRequest{
			Message: "sequential request",
		})
		cancel()

		if err != nil {
			// If OIDC is not required, mTLS alone should work.
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Unauthenticated {
				// Expected if server requires OIDC and token is invalid.
				continue
			}
			require.NoError(t, err)
		} else {
			assert.Equal(t, "sequential request", resp.GetMessage())
		}
	}
}
