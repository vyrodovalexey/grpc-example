//go:build functional

package functional

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/grpc-example/internal/config"
	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

const (
	testIssuer   = "https://issuer.example.com"
	testClientID = "test-client"
	testAudience = "test-client"
	testSubject  = "user@example.com"
)

// setupDefaultOIDCEnv creates a default OIDC test environment.
func setupDefaultOIDCEnv(t *testing.T, verifier *mockTokenVerifier, audience string) *oidcTestEnv {
	t.Helper()

	provider := &mockProvider{verifier: verifier}
	authCfg := config.AuthConfig{
		OIDCEnabled:  true,
		OIDCClientID: testClientID,
		OIDCAudience: audience,
	}

	env, err := setupOIDCServer(provider, authCfg, zap.NewNop())
	require.NoError(t, err)

	t.Cleanup(env.teardown)
	return env
}

func TestFunctional_OIDC_ValidToken(t *testing.T) {
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

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "OIDC test"})
	require.NoError(t, err)
	assert.Equal(t, "OIDC test", resp.GetMessage())
	assert.Greater(t, resp.GetTimestamp(), int64(0))
}

func TestFunctional_OIDC_InvalidToken(t *testing.T) {
	t.Parallel()

	verifier := &mockTokenVerifier{err: fmt.Errorf("invalid token signature")}
	env := setupDefaultOIDCEnv(t, verifier, "")

	conn, client, err := createOIDCClient(env.address, "invalid-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "invalid-token")

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "OIDC authentication failed")
}

func TestFunctional_OIDC_ExpiredToken(t *testing.T) {
	t.Parallel()

	verifier := &mockTokenVerifier{err: fmt.Errorf("token is expired")}
	env := setupDefaultOIDCEnv(t, verifier, "")

	conn, client, err := createOIDCClient(env.address, "expired-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "expired-token")

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestFunctional_OIDC_TokenWithWrongAudience(t *testing.T) {
	t.Parallel()

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{"wrong-audience"},
		fmt.Sprintf(`{"sub":"%s","iss":"%s"}`, testSubject, testIssuer),
	)
	verifier := &mockTokenVerifier{token: token}
	env := setupDefaultOIDCEnv(t, verifier, testAudience)

	conn, client, err := createOIDCClient(env.address, "wrong-audience-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "wrong-audience-token")

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "audience")
}

func TestFunctional_OIDC_TokenWithWrongIssuer(t *testing.T) {
	t.Parallel()

	// The verifier rejects the token because the issuer doesn't match.
	verifier := &mockTokenVerifier{err: fmt.Errorf("issuer mismatch: expected https://correct.example.com")}
	env := setupDefaultOIDCEnv(t, verifier, "")

	conn, client, err := createOIDCClient(env.address, "wrong-issuer-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "wrong-issuer-token")

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestFunctional_OIDC_MissingToken(t *testing.T) {
	t.Parallel()

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	verifier := &mockTokenVerifier{token: token}
	env := setupDefaultOIDCEnv(t, verifier, "")

	conn, client, err := createOIDCClient(env.address, "")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	// Do NOT add a bearer token to the context.
	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "OIDC authentication failed")
}

func TestFunctional_OIDC_TokenWithRequiredClaims(t *testing.T) {
	t.Parallel()

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		`{"sub":"user@example.com","iss":"https://issuer.example.com","role":"admin","scope":"read"}`,
	)
	verifier := &mockTokenVerifier{token: token}
	env := setupDefaultOIDCEnv(t, verifier, testAudience)

	conn, client, err := createOIDCClient(env.address, "valid-claims-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "valid-claims-token")

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "claims test"})
	require.NoError(t, err)
	assert.Equal(t, "claims test", resp.GetMessage())
}

func TestFunctional_OIDC_AllGRPCMethods_Unary(t *testing.T) {
	t.Parallel()

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	verifier := &mockTokenVerifier{token: token}
	env := setupDefaultOIDCEnv(t, verifier, testAudience)

	conn, client, err := createOIDCClient(env.address, "valid-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "valid-token")

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "unary with OIDC"})
	require.NoError(t, err)
	assert.Equal(t, "unary with OIDC", resp.GetMessage())
}

func TestFunctional_OIDC_AllGRPCMethods_ServerStream(t *testing.T) {
	t.Parallel()

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	verifier := &mockTokenVerifier{token: token}
	env := setupDefaultOIDCEnv(t, verifier, testAudience)

	conn, client, err := createOIDCClient(env.address, "valid-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "valid-token")

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

func TestFunctional_OIDC_AllGRPCMethods_BidiStream(t *testing.T) {
	t.Parallel()

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	verifier := &mockTokenVerifier{token: token}
	env := setupDefaultOIDCEnv(t, verifier, testAudience)

	conn, client, err := createOIDCClient(env.address, "valid-token")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	ctx = contextWithBearerToken(ctx, "valid-token")

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	err = stream.Send(&apiv1.BidirectionalRequest{
		Value:     10,
		Operation: "double",
	})
	require.NoError(t, err)

	err = stream.CloseSend()
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, int64(20), resp.GetTransformedValue())
}

func TestFunctional_OIDC_EmptyBearerToken(t *testing.T) {
	t.Parallel()

	token := createIDTokenWithClaims(
		testIssuer, testSubject, []string{testAudience},
		fmt.Sprintf(`{"sub":"%s"}`, testSubject),
	)
	verifier := &mockTokenVerifier{token: token}
	env := setupDefaultOIDCEnv(t, verifier, "")

	conn, client, err := createOIDCClient(env.address, "")
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := newTestContext()
	defer cancel()

	// Send "Bearer " with empty token.
	ctx = contextWithBearerToken(ctx, "")

	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "should fail"})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestFunctional_OIDC_TableDriven(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		verifier *mockTokenVerifier
		audience string
		token    string
		addToken bool
		wantErr  bool
		errCode  codes.Code
	}{
		{
			name: "valid_token_no_audience",
			verifier: &mockTokenVerifier{
				token: createIDTokenWithClaims(
					testIssuer, testSubject, []string{testAudience},
					fmt.Sprintf(`{"sub":"%s"}`, testSubject),
				),
			},
			audience: "",
			token:    "valid-token",
			addToken: true,
			wantErr:  false,
		},
		{
			name: "valid_token_matching_audience",
			verifier: &mockTokenVerifier{
				token: createIDTokenWithClaims(
					testIssuer, testSubject, []string{testAudience},
					fmt.Sprintf(`{"sub":"%s"}`, testSubject),
				),
			},
			audience: testAudience,
			token:    "valid-token",
			addToken: true,
			wantErr:  false,
		},
		{
			name:     "invalid_token",
			verifier: &mockTokenVerifier{err: fmt.Errorf("invalid signature")},
			audience: "",
			token:    "invalid-token",
			addToken: true,
			wantErr:  true,
			errCode:  codes.Unauthenticated,
		},
		{
			name:     "expired_token",
			verifier: &mockTokenVerifier{err: fmt.Errorf("token expired")},
			audience: "",
			token:    "expired-token",
			addToken: true,
			wantErr:  true,
			errCode:  codes.Unauthenticated,
		},
		{
			name: "wrong_audience",
			verifier: &mockTokenVerifier{
				token: createIDTokenWithClaims(
					testIssuer, testSubject, []string{"other-audience"},
					fmt.Sprintf(`{"sub":"%s"}`, testSubject),
				),
			},
			audience: testAudience,
			token:    "wrong-aud-token",
			addToken: true,
			wantErr:  true,
			errCode:  codes.Unauthenticated,
		},
		{
			name: "missing_token",
			verifier: &mockTokenVerifier{
				token: createIDTokenWithClaims(
					testIssuer, testSubject, []string{testAudience},
					fmt.Sprintf(`{"sub":"%s"}`, testSubject),
				),
			},
			audience: "",
			token:    "",
			addToken: false,
			wantErr:  true,
			errCode:  codes.Unauthenticated,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := setupDefaultOIDCEnv(t, tc.verifier, tc.audience)

			conn, client, err := createOIDCClient(env.address, tc.token)
			require.NoError(t, err)
			defer conn.Close()

			ctx, cancel := newTestContext()
			defer cancel()

			if tc.addToken {
				ctx = contextWithBearerToken(ctx, tc.token)
			}

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
