package metrics

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// splitMethodName splits a gRPC full method name into service and method components.
func splitMethodName(fullMethod string) (serviceName string, methodName string) {
	// Full method is in the form "/package.service/method"
	fullMethod = strings.TrimPrefix(fullMethod, "/")
	pos := strings.LastIndex(fullMethod, "/")
	if pos < 0 {
		return "unknown", fullMethod
	}
	return fullMethod[:pos], fullMethod[pos+1:]
}

// gRPC type label values.
const (
	grpcTypeUnary        = "unary"
	grpcTypeServerStream = "server_stream"
	grpcTypeBidiStream   = "bidi_stream"
)

// UnaryServerInterceptor returns a gRPC unary server interceptor that records Prometheus metrics.
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		serviceName, methodName := splitMethodName(info.FullMethod)

		ServerStartedTotal.WithLabelValues(grpcTypeUnary, serviceName, methodName).Inc()
		ServerInFlightRequests.WithLabelValues(grpcTypeUnary, serviceName, methodName).Inc()
		defer ServerInFlightRequests.WithLabelValues(grpcTypeUnary, serviceName, methodName).Dec()

		startTime := time.Now()
		resp, err := handler(ctx, req)
		elapsed := time.Since(startTime).Seconds()

		code := status.Code(err).String()
		ServerHandledTotal.WithLabelValues(grpcTypeUnary, serviceName, methodName, code).Inc()
		ServerHandlingSeconds.WithLabelValues(grpcTypeUnary, serviceName, methodName).Observe(elapsed)

		return resp, err
	}
}

// monitoredServerStream wraps a grpc.ServerStream to count sent and received messages.
type monitoredServerStream struct {
	grpc.ServerStream
	grpcType    string
	serviceName string
	methodName  string
}

// SendMsg records a sent stream message before delegating to the underlying stream.
func (s *monitoredServerStream) SendMsg(m any) error {
	err := s.ServerStream.SendMsg(m)
	if err == nil {
		ServerMsgSentTotal.WithLabelValues(s.grpcType, s.serviceName, s.methodName).Inc()
	}
	return err
}

// RecvMsg records a received stream message after delegating to the underlying stream.
func (s *monitoredServerStream) RecvMsg(m any) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil {
		ServerMsgReceivedTotal.WithLabelValues(s.grpcType, s.serviceName, s.methodName).Inc()
	}
	return err
}

// StreamServerInterceptor returns a gRPC stream server interceptor that records Prometheus metrics.
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		serviceName, methodName := splitMethodName(info.FullMethod)

		grpcType := grpcTypeServerStream
		if info.IsClientStream {
			grpcType = grpcTypeBidiStream
		}

		ServerStartedTotal.WithLabelValues(grpcType, serviceName, methodName).Inc()
		ServerInFlightRequests.WithLabelValues(grpcType, serviceName, methodName).Inc()
		defer ServerInFlightRequests.WithLabelValues(grpcType, serviceName, methodName).Dec()

		wrapped := &monitoredServerStream{
			ServerStream: ss,
			grpcType:     grpcType,
			serviceName:  serviceName,
			methodName:   methodName,
		}

		startTime := time.Now()
		err := handler(srv, wrapped)
		elapsed := time.Since(startTime).Seconds()

		code := status.Code(err).String()
		ServerHandledTotal.WithLabelValues(grpcType, serviceName, methodName, code).Inc()
		ServerHandlingSeconds.WithLabelValues(grpcType, serviceName, methodName).Observe(elapsed)

		return err
	}
}
