//go:build functional

package functional

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apiv1 "github.com/alexey/grpc-example/pkg/api/v1"
)

func TestFunctional_Unary_SimpleMessage(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()
	message := "Hello, gRPC!"

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: message})

	require.NoError(t, err)
	assert.Equal(t, message, resp.GetMessage())
	assert.Greater(t, resp.GetTimestamp(), int64(0))
}

func TestFunctional_Unary_EmptyMessage(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: ""})

	require.NoError(t, err)
	assert.Equal(t, "", resp.GetMessage())
	assert.Greater(t, resp.GetTimestamp(), int64(0))
}

func TestFunctional_Unary_LargeMessage(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()
	// Create a 1KB message
	message := strings.Repeat("A", 1024)

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: message})

	require.NoError(t, err)
	assert.Equal(t, message, resp.GetMessage())
	assert.Len(t, resp.GetMessage(), 1024)
}

func TestFunctional_Unary_UnicodeMessage(t *testing.T) {
	t.Parallel()

	ctx, cancel := newTestContext()
	defer cancel()

	client := getClient()
	message := "Hello, World!"

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: message})

	require.NoError(t, err)
	assert.Equal(t, message, resp.GetMessage())
}

func TestFunctional_Unary_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	const numRequests = 10
	client := getClient()

	var wg sync.WaitGroup
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			ctx, cancel := newTestContext()
			defer cancel()

			message := strings.Repeat("X", idx+1)
			resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: message})
			if err != nil {
				results <- err
				return
			}
			if resp.GetMessage() != message {
				results <- assert.AnError
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

func TestFunctional_Unary_RequestWithDeadline(t *testing.T) {
	t.Parallel()

	// Use a generous deadline that should complete
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := getClient()
	message := "deadline test"

	resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: message})

	require.NoError(t, err)
	assert.Equal(t, message, resp.GetMessage())
}

func TestFunctional_Unary_RequestWithExpiredDeadline(t *testing.T) {
	t.Parallel()

	// Create an already expired context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for context to expire
	time.Sleep(10 * time.Millisecond)

	client := getClient()

	_, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: "expired"})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestFunctional_Unary_TableDriven(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		message string
	}{
		{
			name:    "simple_ascii",
			message: "hello world",
		},
		{
			name:    "numbers",
			message: "12345",
		},
		{
			name:    "special_characters",
			message: "!@#$%^&*()",
		},
		{
			name:    "mixed_content",
			message: "Hello 123 !@#",
		},
		{
			name:    "whitespace",
			message: "  spaces  and\ttabs\n",
		},
		{
			name:    "json_like",
			message: `{"key": "value"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := newTestContext()
			defer cancel()

			client := getClient()

			resp, err := client.Unary(ctx, &apiv1.UnaryRequest{Message: tc.message})

			require.NoError(t, err)
			assert.Equal(t, tc.message, resp.GetMessage())
		})
	}
}
