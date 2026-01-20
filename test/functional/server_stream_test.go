//go:build functional

package functional

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

func TestFunctional_ServerStream_FiveValues(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      5,
		IntervalMs: 10,
	})
	require.NoError(t, err)

	var responses []*apiv1.StreamResponse
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

func TestFunctional_ServerStream_ZeroValues(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      0,
		IntervalMs: 10,
	})
	require.NoError(t, err) // Stream creation succeeds

	// Error is returned on first Recv
	_, err = stream.Recv()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestFunctional_ServerStream_HundredValues(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      100,
		IntervalMs: 10,
	})
	require.NoError(t, err)

	count := 0
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		count++
	}

	assert.Equal(t, 100, count)
}

func TestFunctional_ServerStream_CancelAfterThree(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := getClient()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      10,
		IntervalMs: 50,
	})
	require.NoError(t, err)

	received := 0
	for received < 3 {
		_, err := stream.Recv()
		if err != nil {
			break
		}
		received++
	}

	// Cancel after receiving 3 values
	cancel()

	// Try to receive more - should fail
	_, err = stream.Recv()
	require.Error(t, err)

	assert.Equal(t, 3, received)
}

func TestFunctional_ServerStream_SequentialSequenceNumbers(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      5,
		IntervalMs: 10,
	})
	require.NoError(t, err)

	var sequences []int32
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		sequences = append(sequences, resp.GetSequence())
	}

	require.Len(t, sequences, 5)
	for i, seq := range sequences {
		assert.Equal(t, int32(i+1), seq, "sequence number should be %d but got %d", i+1, seq)
	}
}

func TestFunctional_ServerStream_IncreasingTimestamps(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      5,
		IntervalMs: 20,
	})
	require.NoError(t, err)

	var timestamps []int64
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		timestamps = append(timestamps, resp.GetTimestamp())
	}

	require.Len(t, timestamps, 5)
	for i := 1; i < len(timestamps); i++ {
		assert.Greater(t, timestamps[i], timestamps[i-1],
			"timestamp %d should be greater than timestamp %d", i, i-1)
	}
}

func TestFunctional_ServerStream_CustomInterval(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	start := time.Now()
	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      3,
		IntervalMs: 100,
	})
	require.NoError(t, err)

	count := 0
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		count++
	}
	elapsed := time.Since(start)

	assert.Equal(t, 3, count)
	// Should take at least 300ms (3 * 100ms)
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(300))
}

func TestFunctional_ServerStream_RandomValues(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	stream, err := client.ServerStream(ctx, &apiv1.StreamRequest{
		Count:      10,
		IntervalMs: 10,
	})
	require.NoError(t, err)

	var values []int64
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		values = append(values, resp.GetValue())
	}

	require.Len(t, values, 10)

	// Check that not all values are the same (would be extremely unlikely with random values)
	allSame := true
	for i := 1; i < len(values); i++ {
		if values[i] != values[0] {
			allSame = false
			break
		}
	}
	assert.False(t, allSame, "all values should not be the same")
}

func TestFunctional_ServerStream_TableDriven(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		count         int32
		intervalMs    int32
		expectedCount int
		expectError   bool
		errorCode     codes.Code
	}{
		{
			name:          "single_value",
			count:         1,
			intervalMs:    10,
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "multiple_values",
			count:         5,
			intervalMs:    10,
			expectedCount: 5,
			expectError:   false,
		},
		{
			name:          "negative_count",
			count:         -1,
			intervalMs:    10,
			expectedCount: 0,
			expectError:   true,
			errorCode:     codes.InvalidArgument,
		},
		{
			name:          "invalid_interval_too_small",
			count:         5,
			intervalMs:    5,
			expectedCount: 0,
			expectError:   true,
			errorCode:     codes.InvalidArgument,
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
			require.NoError(t, err) // Stream creation always succeeds

			count := 0
			for {
				_, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					if tc.expectError {
						st, ok := status.FromError(err)
						require.True(t, ok)
						assert.Equal(t, tc.errorCode, st.Code())
						return
					}
					require.NoError(t, err)
				}
				count++
			}

			require.False(t, tc.expectError, "expected error but got none")
			assert.Equal(t, tc.expectedCount, count)
		})
	}
}
