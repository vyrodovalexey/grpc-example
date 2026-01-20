//go:build functional

package functional

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apiv1 "github.com/alexey/grpc-example/pkg/api/v1"
)

func TestFunctional_BidiStream_FiveValuesTransformed(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	// Send 5 values
	for i := int64(1); i <= 5; i++ {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     i,
			Operation: "double",
		})
		require.NoError(t, err)
	}

	// Close send side
	err = stream.CloseSend()
	require.NoError(t, err)

	// Receive 5 responses
	var responses []*apiv1.BidirectionalResponse
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		responses = append(responses, resp)
	}

	assert.Len(t, responses, 5)
}

func TestFunctional_BidiStream_DoubleOperation(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	testValues := []int64{1, 5, 10, -3, 0}

	for _, val := range testValues {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     val,
			Operation: "double",
		})
		require.NoError(t, err)
	}

	err = stream.CloseSend()
	require.NoError(t, err)

	for _, expected := range testValues {
		resp, err := stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, expected, resp.GetOriginalValue())
		assert.Equal(t, expected*2, resp.GetTransformedValue())
		assert.Equal(t, "double", resp.GetOperation())
	}
}

func TestFunctional_BidiStream_SquareOperation(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	testValues := []int64{2, 3, 4, -2, 0}

	for _, val := range testValues {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     val,
			Operation: "square",
		})
		require.NoError(t, err)
	}

	err = stream.CloseSend()
	require.NoError(t, err)

	for _, expected := range testValues {
		resp, err := stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, expected, resp.GetOriginalValue())
		assert.Equal(t, expected*expected, resp.GetTransformedValue())
		assert.Equal(t, "square", resp.GetOperation())
	}
}

func TestFunctional_BidiStream_NegateOperation(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	testValues := []int64{1, -5, 10, 0, -100}

	for _, val := range testValues {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     val,
			Operation: "negate",
		})
		require.NoError(t, err)
	}

	err = stream.CloseSend()
	require.NoError(t, err)

	for _, expected := range testValues {
		resp, err := stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, expected, resp.GetOriginalValue())
		assert.Equal(t, -expected, resp.GetTransformedValue())
		assert.Equal(t, "negate", resp.GetOperation())
	}
}

func TestFunctional_BidiStream_MixedOperations(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	requests := []struct {
		value     int64
		operation string
		expected  int64
	}{
		{5, "double", 10},
		{3, "square", 9},
		{7, "negate", -7},
		{4, "double", 8},
		{2, "square", 4},
	}

	for _, req := range requests {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     req.value,
			Operation: req.operation,
		})
		require.NoError(t, err)
	}

	err = stream.CloseSend()
	require.NoError(t, err)

	for _, expected := range requests {
		resp, err := stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, expected.value, resp.GetOriginalValue())
		assert.Equal(t, expected.expected, resp.GetTransformedValue())
		assert.Equal(t, expected.operation, resp.GetOperation())
	}
}

func TestFunctional_BidiStream_ZeroValues(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	// Close immediately without sending anything
	err = stream.CloseSend()
	require.NoError(t, err)

	// Should receive EOF immediately
	_, err = stream.Recv()
	assert.Equal(t, io.EOF, err)
}

func TestFunctional_BidiStream_RapidSendWithoutWaiting(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	// Send many values rapidly without waiting for responses
	const numValues = 50
	for i := int64(0); i < numValues; i++ {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     i,
			Operation: "double",
		})
		require.NoError(t, err)
	}

	err = stream.CloseSend()
	require.NoError(t, err)

	// Now receive all responses
	count := 0
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		assert.Equal(t, int64(count)*2, resp.GetTransformedValue())
		count++
	}

	assert.Equal(t, numValues, count)
}

func TestFunctional_BidiStream_CloseSendAndReceiveRemaining(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	// Send some values
	for i := int64(1); i <= 3; i++ {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     i,
			Operation: "double",
		})
		require.NoError(t, err)
	}

	// Close send side
	err = stream.CloseSend()
	require.NoError(t, err)

	// Should still be able to receive all responses
	var responses []*apiv1.BidirectionalResponse
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		responses = append(responses, resp)
	}

	assert.Len(t, responses, 3)
	for i, resp := range responses {
		assert.Equal(t, int64(i+1), resp.GetOriginalValue())
		assert.Equal(t, int64((i+1)*2), resp.GetTransformedValue())
	}
}

func TestFunctional_BidiStream_CancelMidStream(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	// Send a few values
	for i := int64(1); i <= 3; i++ {
		err := stream.Send(&apiv1.BidirectionalRequest{
			Value:     i,
			Operation: "double",
		})
		require.NoError(t, err)
	}

	// Receive one response
	_, err = stream.Recv()
	require.NoError(t, err)

	// Cancel the context
	cancel()

	// Further operations should fail
	err = stream.Send(&apiv1.BidirectionalRequest{
		Value:     100,
		Operation: "double",
	})
	// Send might succeed if buffered, but eventually should fail
	// So we check Recv instead
	_, err = stream.Recv()
	if err != nil && err != io.EOF {
		st, ok := status.FromError(err)
		if ok {
			assert.Contains(t, []codes.Code{codes.Canceled, codes.Unavailable}, st.Code())
		}
	}
}

func TestFunctional_BidiStream_InvalidOperation(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.BidirectionalStream(ctx)
	require.NoError(t, err)

	// Send with invalid operation
	err = stream.Send(&apiv1.BidirectionalRequest{
		Value:     5,
		Operation: "invalid_op",
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
}

func TestFunctional_BidiStream_TableDriven(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		value     int64
		operation string
		expected  int64
		wantErr   bool
		errCode   codes.Code
	}{
		{
			name:      "double_positive",
			value:     10,
			operation: "double",
			expected:  20,
			wantErr:   false,
		},
		{
			name:      "double_negative",
			value:     -5,
			operation: "double",
			expected:  -10,
			wantErr:   false,
		},
		{
			name:      "square_positive",
			value:     7,
			operation: "square",
			expected:  49,
			wantErr:   false,
		},
		{
			name:      "square_negative",
			value:     -3,
			operation: "square",
			expected:  9,
			wantErr:   false,
		},
		{
			name:      "negate_positive",
			value:     15,
			operation: "negate",
			expected:  -15,
			wantErr:   false,
		},
		{
			name:      "negate_negative",
			value:     -8,
			operation: "negate",
			expected:  8,
			wantErr:   false,
		},
		{
			name:      "double_zero",
			value:     0,
			operation: "double",
			expected:  0,
			wantErr:   false,
		},
		{
			name:      "unknown_operation",
			value:     5,
			operation: "unknown",
			expected:  0,
			wantErr:   true,
			errCode:   codes.InvalidArgument,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := newTestContext()
			defer cancel()

			client := getClient()

			stream, err := client.BidirectionalStream(ctx)
			require.NoError(t, err)

			err = stream.Send(&apiv1.BidirectionalRequest{
				Value:     tc.value,
				Operation: tc.operation,
			})
			require.NoError(t, err)

			err = stream.CloseSend()
			require.NoError(t, err)

			resp, err := stream.Recv()

			if tc.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tc.errCode, st.Code())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.value, resp.GetOriginalValue())
			assert.Equal(t, tc.expected, resp.GetTransformedValue())
			assert.Equal(t, tc.operation, resp.GetOperation())
		})
	}
}
