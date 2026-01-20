//go:build functional

package functional

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	apiv1 "github.com/alexey/grpc-example/pkg/api/v1"
)

func TestFunctional_Error_ConnectToWrongPort(t *testing.T) {
	t.Parallel()

	// Find an unused port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wrongPort := listener.Addr().String()
	listener.Close() // Close immediately so nothing is listening

	// Try to connect to the wrong port
	conn, err := grpc.NewClient(
		wrongPort,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err) // NewClient doesn't actually connect
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// The actual connection attempt happens here
	_, err = client.Unary(ctx, &apiv1.UnaryRequest{Message: "test"})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	// Should be Unavailable when server is not reachable
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestFunctional_Error_RequestTimeout(t *testing.T) {
	t.Parallel()

	// Create a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for context to expire
	time.Sleep(10 * time.Millisecond)

	client := getClient()

	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "timeout test"})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestFunctional_Error_ServerShutdownMidRequest(t *testing.T) {
	// Don't run in parallel as we're creating our own server
	// t.Parallel()

	// Create a separate server for this test
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()

	logger := zap.NewNop()
	grpcServer := grpc.NewServer()
	testService := newTestService(logger)
	apiv1.RegisterTestServiceServer(grpcServer, testService)

	// Start server
	serverDone := make(chan struct{})
	go func() {
		_ = grpcServer.Serve(listener)
		close(serverDone)
	}()

	// Connect to server
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := apiv1.NewTestServiceClient(conn)

	// Verify server is working
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "before shutdown"})
	require.NoError(t, err)
	assert.Equal(t, "before shutdown", resp.GetMessage())

	// Start a streaming request
	streamCtx, streamCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer streamCancel()

	stream, err := client.ServerStream(streamCtx, &apiv1.StreamRequest{
		Count:      100,
		IntervalMs: 100,
	})
	require.NoError(t, err)

	// Receive a few responses
	for i := 0; i < 2; i++ {
		_, err := stream.Recv()
		require.NoError(t, err)
	}

	// Stop the server mid-stream
	grpcServer.Stop()

	// Wait for server to stop
	<-serverDone

	// Try to receive more - should fail
	_, err = stream.Recv()
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			// Could be Unavailable, Canceled, or Internal depending on timing
			assert.Contains(t, []codes.Code{codes.Unavailable, codes.Canceled, codes.Internal}, st.Code())
		}
	}
}

func TestFunctional_Error_StreamCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	client := getClient()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      100,
		IntervalMs: 50,
	})
	require.NoError(t, err)

	// Receive a few responses
	for i := 0; i < 3; i++ {
		_, err := stream.Recv()
		require.NoError(t, err)
	}

	// Cancel the context
	cancel()

	// Try to receive more - should fail with Canceled
	_, err = stream.Recv()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Canceled, st.Code())
}

func TestFunctional_Error_InvalidStreamParameters(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		count      int32
		intervalMs int32
		errCode    codes.Code
	}{
		{
			name:       "negative_count",
			count:      -1,
			intervalMs: 10,
			errCode:    codes.InvalidArgument,
		},
		{
			name:       "zero_count",
			count:      0,
			intervalMs: 10,
			errCode:    codes.InvalidArgument,
		},
		{
			name:       "interval_too_small",
			count:      5,
			intervalMs: 5,
			errCode:    codes.InvalidArgument,
		},
		{
			name:       "negative_interval",
			count:      5,
			intervalMs: -1,
			errCode:    codes.InvalidArgument,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := newTestContext()
			defer cancel()

			client := getClient()

			stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
				Count:      tc.count,
				IntervalMs: tc.intervalMs,
			})
			require.NoError(t, err) // Stream creation succeeds

			// Error is returned on first Recv
			_, err = stream.Recv()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tc.errCode, st.Code())
		})
	}
}

func TestFunctional_Error_BidiStreamInvalidOperation(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	// Send with invalid operation
	err = stream.Send(&apiv1.BidirectionalRequest{
		Value:     10,
		Operation: "multiply", // Invalid operation
	})
	require.NoError(t, err)

	err = stream.CloseSend()
	require.NoError(t, err)

	// Should receive an error
	_, err = stream.Recv()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "unknown operation")
}

func TestFunctional_Error_ContextCancelledBeforeRequest(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client := getClient()

	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "cancelled"})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Canceled, st.Code())
}

func TestFunctional_Error_MultipleErrors(t *testing.T) {
	t.Parallel()

	client := getClient()

	// Test multiple error scenarios in sequence
	errorScenarios := []struct {
		name    string
		runTest func(t *testing.T)
	}{
		{
			name: "expired_deadline",
			runTest: func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				defer cancel()
				time.Sleep(10 * time.Millisecond)

				_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "test"})
				require.Error(t, err)
			},
		},
		{
			name: "cancelled_context",
			runTest: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "test"})
				require.Error(t, err)
			},
		},
		{
			name: "invalid_stream_params",
			runTest: func(t *testing.T) {
				ctx, cancel := newTestContext()
				defer cancel()

				stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
					Count:      0,
					IntervalMs: 10,
				})
				require.NoError(t, err) // Stream creation succeeds

				// Error is returned on first Recv
				_, err = stream.Recv()
				require.Error(t, err)
			},
		},
	}

	for _, scenario := range errorScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			scenario.runTest(t)
		})
	}
}
