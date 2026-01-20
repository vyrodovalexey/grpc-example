//go:build functional

package functional

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apiv1 "github.com/alexey/grpc-example/pkg/api/v1"
)

const (
	defaultIntervalMs = 1000
	opDouble          = "double"
	opSquare          = "square"
	opNegate          = "negate"
	maxCount          = 10000
	maxIntervalMs     = 60000
	minIntervalMs     = 10
)

// testServiceImpl implements the TestServiceServer interface for testing.
type testServiceImpl struct {
	apiv1.UnimplementedTestServiceServer
	logger *zap.Logger
}

// newTestService creates a new test service instance.
func newTestService(logger *zap.Logger) *testServiceImpl {
	return &testServiceImpl{
		logger: logger,
	}
}

// Unary handles unary RPC requests.
func (s *testServiceImpl) Unary(ctx context.Context, req *apiv1.UnaryRequest) (*apiv1.UnaryResponse, error) {
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	return &apiv1.UnaryResponse{
		Message:   req.GetMessage(),
		Timestamp: time.Now().UnixNano(),
	}, nil
}

// ServerStream handles server streaming RPC requests.
func (s *testServiceImpl) ServerStream(
	req *apiv1.StreamRequest,
	stream apiv1.TestService_ServerStreamServer,
) error {
	count := req.GetCount()
	intervalMs := req.GetIntervalMs()

	if err := validateStreamRequest(count, intervalMs); err != nil {
		return err
	}

	if intervalMs == 0 {
		intervalMs = defaultIntervalMs
	}

	return s.sendStreamResponses(stream, count, intervalMs)
}

// validateStreamRequest validates the stream request parameters.
func validateStreamRequest(count, intervalMs int32) error {
	if count <= 0 || count > maxCount {
		return status.Errorf(codes.InvalidArgument, "count must be between 1 and %d", maxCount)
	}
	if intervalMs < 0 || intervalMs > maxIntervalMs {
		return status.Errorf(codes.InvalidArgument, "interval_ms must be between 0 and %d", maxIntervalMs)
	}
	if intervalMs > 0 && intervalMs < minIntervalMs {
		return status.Errorf(codes.InvalidArgument, "interval_ms must be at least %d when specified", minIntervalMs)
	}
	return nil
}

// sendStreamResponses sends stream responses at the specified interval.
func (s *testServiceImpl) sendStreamResponses(
	stream apiv1.TestService_ServerStreamServer,
	count, intervalMs int32,
) error {
	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for i := int32(0); i < count; i++ {
		select {
		case <-stream.Context().Done():
			return status.Error(codes.Canceled, "stream cancelled by client")
		case <-ticker.C:
			resp := &apiv1.StreamResponse{
				Value:     rand.Int64(),
				Sequence:  i + 1,
				Timestamp: time.Now().UnixNano(),
			}

			if err := stream.Send(resp); err != nil {
				return status.Errorf(codes.Internal, "failed to send response: %v", err)
			}
		}
	}

	return nil
}

// BidirectionalStream handles bidirectional streaming RPC requests.
func (s *testServiceImpl) BidirectionalStream(
	stream apiv1.TestService_BidirectionalStreamServer,
) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to receive: %v", err)
		}

		if err := s.processBidirectionalRequest(stream, req); err != nil {
			return err
		}
	}
}

// processBidirectionalRequest processes a single bidirectional request.
func (s *testServiceImpl) processBidirectionalRequest(
	stream apiv1.TestService_BidirectionalStreamServer,
	req *apiv1.BidirectionalRequest,
) error {
	select {
	case <-stream.Context().Done():
		return status.Error(codes.Canceled, "stream cancelled")
	default:
	}

	originalValue := req.GetValue()
	operation := req.GetOperation()
	transformedValue, err := transformValue(originalValue, operation)
	if err != nil {
		return err
	}

	resp := &apiv1.BidirectionalResponse{
		OriginalValue:    originalValue,
		TransformedValue: transformedValue,
		Operation:        operation,
		Timestamp:        time.Now().UnixNano(),
	}

	if err := stream.Send(resp); err != nil {
		return status.Errorf(codes.Internal, "failed to send response: %v", err)
	}

	return nil
}

// transformValue applies the specified operation to the value.
func transformValue(value int64, operation string) (int64, error) {
	switch operation {
	case opDouble:
		return value * 2, nil
	case opSquare:
		return value * value, nil
	case opNegate:
		return -value, nil
	default:
		return 0, status.Errorf(codes.InvalidArgument, "unknown operation: %s (valid: double, square, negate)", operation)
	}
}
