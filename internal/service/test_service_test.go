// Package service_test provides unit tests for the service package.
package service_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/alexey/grpc-example/internal/service"
	apiv1 "github.com/alexey/grpc-example/pkg/api/v1"
)

// mockServerStream implements grpc.ServerStreamingServer[StreamResponse] for testing.
type mockServerStream struct {
	ctx       context.Context
	responses []*apiv1.StreamResponse
	sendErr   error
}

func (m *mockServerStream) Send(resp *apiv1.StreamResponse) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.responses = append(m.responses, resp)
	return nil
}

func (m *mockServerStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockServerStream) SendHeader(metadata.MD) error { return nil }
func (m *mockServerStream) SetTrailer(metadata.MD)       {}
func (m *mockServerStream) Context() context.Context     { return m.ctx }
func (m *mockServerStream) SendMsg(interface{}) error    { return nil }
func (m *mockServerStream) RecvMsg(interface{}) error    { return nil }

// mockBidirectionalStream implements grpc.BidiStreamingServer for testing.
type mockBidirectionalStream struct {
	ctx       context.Context
	requests  []*apiv1.BidirectionalRequest
	responses []*apiv1.BidirectionalResponse
	recvIndex int
	sendErr   error
	recvErr   error
}

func (m *mockBidirectionalStream) Send(resp *apiv1.BidirectionalResponse) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.responses = append(m.responses, resp)
	return nil
}

func (m *mockBidirectionalStream) Recv() (*apiv1.BidirectionalRequest, error) {
	if m.recvErr != nil {
		return nil, m.recvErr
	}
	if m.recvIndex >= len(m.requests) {
		return nil, io.EOF
	}
	req := m.requests[m.recvIndex]
	m.recvIndex++
	return req, nil
}

func (m *mockBidirectionalStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockBidirectionalStream) SendHeader(metadata.MD) error { return nil }
func (m *mockBidirectionalStream) SetTrailer(metadata.MD)       {}
func (m *mockBidirectionalStream) Context() context.Context     { return m.ctx }
func (m *mockBidirectionalStream) SendMsg(interface{}) error    { return nil }
func (m *mockBidirectionalStream) RecvMsg(interface{}) error    { return nil }

func newTestLogger() *zap.Logger {
	return zap.NewNop()
}

func TestNewTestService(t *testing.T) {
	// Arrange
	logger := newTestLogger()

	// Act
	svc := service.NewTestService(logger)

	// Assert
	require.NotNil(t, svc)
}

func TestUnary(t *testing.T) {
	tests := []struct {
		name        string
		request     *apiv1.UnaryRequest
		ctxFunc     func() context.Context
		wantErr     bool
		errCode     codes.Code
		wantMessage string
	}{
		{
			name:        "valid request with message",
			request:     &apiv1.UnaryRequest{Message: "hello world"},
			ctxFunc:     func() context.Context { return context.Background() },
			wantErr:     false,
			wantMessage: "hello world",
		},
		{
			name:        "empty message",
			request:     &apiv1.UnaryRequest{Message: ""},
			ctxFunc:     func() context.Context { return context.Background() },
			wantErr:     false,
			wantMessage: "",
		},
		{
			name:    "nil request",
			request: nil,
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: false,
			// GetMessage() on nil returns empty string
			wantMessage: "",
		},
		{
			name:    "cancelled context",
			request: &apiv1.UnaryRequest{Message: "test"},
			ctxFunc: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErr: true,
			errCode: codes.Canceled,
		},
		{
			name:        "long message",
			request:     &apiv1.UnaryRequest{Message: "this is a very long message that should still work correctly"},
			ctxFunc:     func() context.Context { return context.Background() },
			wantErr:     false,
			wantMessage: "this is a very long message that should still work correctly",
		},
		{
			name:        "special characters",
			request:     &apiv1.UnaryRequest{Message: "hello\nworld\t!@#$%^&*()"},
			ctxFunc:     func() context.Context { return context.Background() },
			wantErr:     false,
			wantMessage: "hello\nworld\t!@#$%^&*()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := newTestLogger()
			svc := service.NewTestService(logger)
			ctx := tt.ctxFunc()

			// Act
			resp, err := svc.Unary(ctx, tt.request)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.errCode, st.Code())
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, tt.wantMessage, resp.GetMessage())
				assert.Greater(t, resp.GetTimestamp(), int64(0))
			}
		})
	}
}

func TestServerStream(t *testing.T) {
	tests := []struct {
		name          string
		request       *apiv1.StreamRequest
		ctxFunc       func() (context.Context, context.CancelFunc)
		sendErr       error
		wantErr       bool
		errCode       codes.Code
		wantResponses int
	}{
		{
			name:    "stream with count=3",
			request: &apiv1.StreamRequest{Count: 3, IntervalMs: 10},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr:       false,
			wantResponses: 3,
		},
		{
			name:    "stream with count=1",
			request: &apiv1.StreamRequest{Count: 1, IntervalMs: 10},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr:       false,
			wantResponses: 1,
		},
		{
			name:    "stream with count=0 - invalid",
			request: &apiv1.StreamRequest{Count: 0, IntervalMs: 10},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "stream with negative count - invalid",
			request: &apiv1.StreamRequest{Count: -1, IntervalMs: 10},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "stream with count exceeding max",
			request: &apiv1.StreamRequest{Count: 10001, IntervalMs: 10},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "stream with negative interval - invalid",
			request: &apiv1.StreamRequest{Count: 3, IntervalMs: -1},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "stream with interval too small",
			request: &apiv1.StreamRequest{Count: 3, IntervalMs: 5},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "stream with interval exceeding max",
			request: &apiv1.StreamRequest{Count: 3, IntervalMs: 60001},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "stream with zero interval uses default",
			request: &apiv1.StreamRequest{Count: 1, IntervalMs: 0},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			wantErr:       false,
			wantResponses: 1,
		},
		{
			name:    "send error",
			request: &apiv1.StreamRequest{Count: 3, IntervalMs: 10},
			ctxFunc: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			sendErr: errors.New("send failed"),
			wantErr: true,
			errCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := newTestLogger()
			svc := service.NewTestService(logger)
			ctx, cancel := tt.ctxFunc()
			defer cancel()

			stream := &mockServerStream{
				ctx:       ctx,
				responses: make([]*apiv1.StreamResponse, 0),
				sendErr:   tt.sendErr,
			}

			// Act
			err := svc.ServerStream(tt.request, stream)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.errCode, st.Code())
			} else {
				require.NoError(t, err)
				assert.Len(t, stream.responses, tt.wantResponses)

				// Verify sequence numbers
				for i, resp := range stream.responses {
					assert.Equal(t, int32(i+1), resp.GetSequence())
					assert.Greater(t, resp.GetTimestamp(), int64(0))
				}
			}
		})
	}
}

func TestServerStream_ContextCancellation(t *testing.T) {
	// Arrange
	logger := newTestLogger()
	svc := service.NewTestService(logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	stream := &mockServerStream{
		ctx:       ctx,
		responses: make([]*apiv1.StreamResponse, 0),
	}

	req := &apiv1.StreamRequest{Count: 100, IntervalMs: 10}

	// Act
	err := svc.ServerStream(req, stream)

	// Assert
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Canceled, st.Code())
}

func TestBidirectionalStream(t *testing.T) {
	tests := []struct {
		name         string
		requests     []*apiv1.BidirectionalRequest
		ctxFunc      func() context.Context
		sendErr      error
		recvErr      error
		wantErr      bool
		errCode      codes.Code
		validateResp func(t *testing.T, responses []*apiv1.BidirectionalResponse)
	}{
		{
			name: "double operation",
			requests: []*apiv1.BidirectionalRequest{
				{Value: 5, Operation: "double"},
			},
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: false,
			validateResp: func(t *testing.T, responses []*apiv1.BidirectionalResponse) {
				require.Len(t, responses, 1)
				assert.Equal(t, int64(5), responses[0].GetOriginalValue())
				assert.Equal(t, int64(10), responses[0].GetTransformedValue())
				assert.Equal(t, "double", responses[0].GetOperation())
			},
		},
		{
			name: "square operation",
			requests: []*apiv1.BidirectionalRequest{
				{Value: 4, Operation: "square"},
			},
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: false,
			validateResp: func(t *testing.T, responses []*apiv1.BidirectionalResponse) {
				require.Len(t, responses, 1)
				assert.Equal(t, int64(4), responses[0].GetOriginalValue())
				assert.Equal(t, int64(16), responses[0].GetTransformedValue())
				assert.Equal(t, "square", responses[0].GetOperation())
			},
		},
		{
			name: "negate operation",
			requests: []*apiv1.BidirectionalRequest{
				{Value: 7, Operation: "negate"},
			},
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: false,
			validateResp: func(t *testing.T, responses []*apiv1.BidirectionalResponse) {
				require.Len(t, responses, 1)
				assert.Equal(t, int64(7), responses[0].GetOriginalValue())
				assert.Equal(t, int64(-7), responses[0].GetTransformedValue())
				assert.Equal(t, "negate", responses[0].GetOperation())
			},
		},
		{
			name: "negate negative value",
			requests: []*apiv1.BidirectionalRequest{
				{Value: -10, Operation: "negate"},
			},
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: false,
			validateResp: func(t *testing.T, responses []*apiv1.BidirectionalResponse) {
				require.Len(t, responses, 1)
				assert.Equal(t, int64(-10), responses[0].GetOriginalValue())
				assert.Equal(t, int64(10), responses[0].GetTransformedValue())
			},
		},
		{
			name: "unknown operation",
			requests: []*apiv1.BidirectionalRequest{
				{Value: 5, Operation: "unknown"},
			},
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name: "empty operation",
			requests: []*apiv1.BidirectionalRequest{
				{Value: 5, Operation: ""},
			},
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name:     "empty stream",
			requests: []*apiv1.BidirectionalRequest{},
			ctxFunc:  func() context.Context { return context.Background() },
			wantErr:  false,
			validateResp: func(t *testing.T, responses []*apiv1.BidirectionalResponse) {
				assert.Empty(t, responses)
			},
		},
		{
			name: "multiple operations",
			requests: []*apiv1.BidirectionalRequest{
				{Value: 2, Operation: "double"},
				{Value: 3, Operation: "square"},
				{Value: 5, Operation: "negate"},
			},
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: false,
			validateResp: func(t *testing.T, responses []*apiv1.BidirectionalResponse) {
				require.Len(t, responses, 3)
				assert.Equal(t, int64(4), responses[0].GetTransformedValue())  // 2*2
				assert.Equal(t, int64(9), responses[1].GetTransformedValue())  // 3*3
				assert.Equal(t, int64(-5), responses[2].GetTransformedValue()) // -5
			},
		},
		{
			name: "zero value operations",
			requests: []*apiv1.BidirectionalRequest{
				{Value: 0, Operation: "double"},
				{Value: 0, Operation: "square"},
				{Value: 0, Operation: "negate"},
			},
			ctxFunc: func() context.Context { return context.Background() },
			wantErr: false,
			validateResp: func(t *testing.T, responses []*apiv1.BidirectionalResponse) {
				require.Len(t, responses, 3)
				assert.Equal(t, int64(0), responses[0].GetTransformedValue())
				assert.Equal(t, int64(0), responses[1].GetTransformedValue())
				assert.Equal(t, int64(0), responses[2].GetTransformedValue())
			},
		},
		{
			name: "send error",
			requests: []*apiv1.BidirectionalRequest{
				{Value: 5, Operation: "double"},
			},
			ctxFunc: func() context.Context { return context.Background() },
			sendErr: errors.New("send failed"),
			wantErr: true,
			errCode: codes.Internal,
		},
		{
			name:     "receive error",
			requests: nil,
			ctxFunc:  func() context.Context { return context.Background() },
			recvErr:  errors.New("receive failed"),
			wantErr:  true,
			errCode:  codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := newTestLogger()
			svc := service.NewTestService(logger)

			stream := &mockBidirectionalStream{
				ctx:       tt.ctxFunc(),
				requests:  tt.requests,
				responses: make([]*apiv1.BidirectionalResponse, 0),
				sendErr:   tt.sendErr,
				recvErr:   tt.recvErr,
			}

			// Act
			err := svc.BidirectionalStream(stream)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.errCode, st.Code())
			} else {
				require.NoError(t, err)
				if tt.validateResp != nil {
					tt.validateResp(t, stream.responses)
				}
			}
		})
	}
}

func TestBidirectionalStream_ContextCancellation(t *testing.T) {
	// Arrange
	logger := newTestLogger()
	svc := service.NewTestService(logger)

	ctx, cancel := context.WithCancel(context.Background())

	// Create a stream that will check context on first receive
	stream := &mockBidirectionalStreamWithCancelCheck{
		ctx:       ctx,
		cancel:    cancel,
		responses: make([]*apiv1.BidirectionalResponse, 0),
	}

	// Act
	err := svc.BidirectionalStream(stream)

	// Assert
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Canceled, st.Code())
}

// mockBidirectionalStreamWithCancelCheck cancels context after first receive.
type mockBidirectionalStreamWithCancelCheck struct {
	ctx       context.Context
	cancel    context.CancelFunc
	responses []*apiv1.BidirectionalResponse
	recvCount int
}

func (m *mockBidirectionalStreamWithCancelCheck) Send(resp *apiv1.BidirectionalResponse) error {
	m.responses = append(m.responses, resp)
	return nil
}

func (m *mockBidirectionalStreamWithCancelCheck) Recv() (*apiv1.BidirectionalRequest, error) {
	m.recvCount++
	if m.recvCount == 1 {
		// Return a valid request first time
		return &apiv1.BidirectionalRequest{Value: 5, Operation: "double"}, nil
	}
	// Cancel context and return another request
	m.cancel()
	return &apiv1.BidirectionalRequest{Value: 10, Operation: "double"}, nil
}

func (m *mockBidirectionalStreamWithCancelCheck) SetHeader(metadata.MD) error  { return nil }
func (m *mockBidirectionalStreamWithCancelCheck) SendHeader(metadata.MD) error { return nil }
func (m *mockBidirectionalStreamWithCancelCheck) SetTrailer(metadata.MD)       {}
func (m *mockBidirectionalStreamWithCancelCheck) Context() context.Context     { return m.ctx }
func (m *mockBidirectionalStreamWithCancelCheck) SendMsg(interface{}) error    { return nil }
func (m *mockBidirectionalStreamWithCancelCheck) RecvMsg(interface{}) error    { return nil }

func TestTransformValueEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		value     int64
		operation string
		want      int64
	}{
		{
			name:      "double max int32",
			value:     2147483647,
			operation: "double",
			want:      4294967294,
		},
		{
			name:      "square large number",
			value:     1000000,
			operation: "square",
			want:      1000000000000,
		},
		{
			name:      "negate min int64",
			value:     -9223372036854775807,
			operation: "negate",
			want:      9223372036854775807,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			logger := newTestLogger()
			svc := service.NewTestService(logger)

			stream := &mockBidirectionalStream{
				ctx: context.Background(),
				requests: []*apiv1.BidirectionalRequest{
					{Value: tt.value, Operation: tt.operation},
				},
				responses: make([]*apiv1.BidirectionalResponse, 0),
			}

			// Act
			err := svc.BidirectionalStream(stream)

			// Assert
			require.NoError(t, err)
			require.Len(t, stream.responses, 1)
			assert.Equal(t, tt.want, stream.responses[0].GetTransformedValue())
		})
	}
}

func TestUnary_ResponseTimestamp(t *testing.T) {
	// Arrange
	logger := newTestLogger()
	svc := service.NewTestService(logger)
	ctx := context.Background()
	req := &apiv1.UnaryRequest{Message: "test"}

	// Act
	resp1, err1 := svc.Unary(ctx, req)
	resp2, err2 := svc.Unary(ctx, req)

	// Assert
	require.NoError(t, err1)
	require.NoError(t, err2)
	// Timestamps should be different (or at least not decrease)
	assert.GreaterOrEqual(t, resp2.GetTimestamp(), resp1.GetTimestamp())
}

func TestBidirectionalStream_ResponseTimestamp(t *testing.T) {
	// Arrange
	logger := newTestLogger()
	svc := service.NewTestService(logger)

	stream := &mockBidirectionalStream{
		ctx: context.Background(),
		requests: []*apiv1.BidirectionalRequest{
			{Value: 1, Operation: "double"},
			{Value: 2, Operation: "double"},
		},
		responses: make([]*apiv1.BidirectionalResponse, 0),
	}

	// Act
	err := svc.BidirectionalStream(stream)

	// Assert
	require.NoError(t, err)
	require.Len(t, stream.responses, 2)
	// Both responses should have valid timestamps
	assert.Greater(t, stream.responses[0].GetTimestamp(), int64(0))
	assert.Greater(t, stream.responses[1].GetTimestamp(), int64(0))
}
