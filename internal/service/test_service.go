// Package service provides the gRPC service implementations.
package service

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apiv1 "github.com/vyrodovalexey/grpc-example/pkg/api/v1"
)

const (
	// Default interval for streaming operations.
	defaultIntervalMs = 1000

	// Operation types for bidirectional stream.
	opDouble = "double"
	opSquare = "square"
	opNegate = "negate"

	// Limits for validation.
	maxCount      = 10000
	maxIntervalMs = 60000
	minIntervalMs = 10
)

// TestService implements the TestServiceServer interface.
type TestService struct {
	apiv1.UnimplementedTestServiceServer
	logger *zap.Logger
}

// NewTestService creates a new TestService instance.
func NewTestService(logger *zap.Logger) *TestService {
	return &TestService{
		logger: logger.Named("test_service"),
	}
}

// Unary handles unary RPC requests by echoing the message with a timestamp.
func (s *TestService) Unary(ctx context.Context, req *apiv1.UnaryRequest) (*apiv1.UnaryResponse, error) {
	s.logger.Info("received unary request",
		zap.String("message", req.GetMessage()),
	)

	select {
	case <-ctx.Done():
		s.logger.Warn("unary request cancelled")
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	return &apiv1.UnaryResponse{
		Message:   req.GetMessage(),
		Timestamp: time.Now().UnixNano(),
	}, nil
}

// ServerStream handles server streaming RPC requests.
func (s *TestService) ServerStream(
	req *apiv1.StreamRequest,
	stream apiv1.TestService_ServerStreamServer,
) error {
	count := req.GetCount()
	intervalMs := req.GetIntervalMs()

	if err := validateStreamRequest(count, intervalMs); err != nil {
		s.logger.Error("invalid stream request", zap.Error(err))
		return err
	}

	if intervalMs == 0 {
		intervalMs = defaultIntervalMs
	}

	s.logger.Info("starting server stream",
		zap.Int32("count", count),
		zap.Int32("interval_ms", intervalMs),
	)

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
func (s *TestService) sendStreamResponses(
	stream apiv1.TestService_ServerStreamServer,
	count, intervalMs int32,
) error {
	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for i := int32(0); i < count; i++ {
		select {
		case <-stream.Context().Done():
			s.logger.Info("server stream cancelled by client", zap.Int32("sent", i))
			return status.Error(codes.Canceled, "stream cancelled by client")
		case <-ticker.C:
			resp := &apiv1.StreamResponse{
				Value:     rand.Int64(),
				Sequence:  i + 1,
				Timestamp: time.Now().UnixNano(),
			}

			if err := stream.Send(resp); err != nil {
				s.logger.Error("failed to send stream response", zap.Error(err), zap.Int32("sequence", i+1))
				return status.Errorf(codes.Internal, "failed to send response: %v", err)
			}

			s.logger.Debug("sent stream response", zap.Int32("sequence", i+1))
		}
	}

	s.logger.Info("server stream completed", zap.Int32("total_sent", count))
	return nil
}

// BidirectionalStream handles bidirectional streaming RPC requests.
func (s *TestService) BidirectionalStream(
	stream apiv1.TestService_BidirectionalStreamServer,
) error {
	s.logger.Info("starting bidirectional stream")

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			s.logger.Info("bidirectional stream completed by client")
			return nil
		}
		if err != nil {
			s.logger.Error("failed to receive from stream", zap.Error(err))
			return status.Errorf(codes.Internal, "failed to receive: %v", err)
		}

		if err := s.processBidirectionalRequest(stream, req); err != nil {
			return err
		}
	}
}

// processBidirectionalRequest processes a single bidirectional request.
func (s *TestService) processBidirectionalRequest(
	stream apiv1.TestService_BidirectionalStreamServer,
	req *apiv1.BidirectionalRequest,
) error {
	select {
	case <-stream.Context().Done():
		s.logger.Info("bidirectional stream cancelled")
		return status.Error(codes.Canceled, "stream cancelled")
	default:
	}

	originalValue := req.GetValue()
	operation := req.GetOperation()
	transformedValue, err := transformValue(originalValue, operation)
	if err != nil {
		s.logger.Warn("invalid operation", zap.String("operation", operation))
		return err
	}

	resp := &apiv1.BidirectionalResponse{
		OriginalValue:    originalValue,
		TransformedValue: transformedValue,
		Operation:        operation,
		Timestamp:        time.Now().UnixNano(),
	}

	if err := stream.Send(resp); err != nil {
		s.logger.Error("failed to send bidirectional response", zap.Error(err))
		return status.Errorf(codes.Internal, "failed to send response: %v", err)
	}

	s.logger.Debug("processed bidirectional request",
		zap.Int64("original", originalValue),
		zap.Int64("transformed", transformedValue),
		zap.String("operation", operation),
	)

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
