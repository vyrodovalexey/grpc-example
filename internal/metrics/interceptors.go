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

// UnaryServerInterceptor returns a gRPC unary server interceptor that records Prometheus metrics.
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		serviceName, methodName := splitMethodName(info.FullMethod)

		ServerStartedTotal.WithLabelValues("unary", serviceName, methodName).Inc()

		startTime := time.Now()
		resp, err := handler(ctx, req)
		elapsed := time.Since(startTime).Seconds()

		code := status.Code(err).String()
		ServerHandledTotal.WithLabelValues("unary", serviceName, methodName, code).Inc()
		ServerHandlingSeconds.WithLabelValues("unary", serviceName, methodName).Observe(elapsed)

		return resp, err
	}
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

		grpcType := "server_stream"
		if info.IsClientStream {
			grpcType = "bidi_stream"
		}

		ServerStartedTotal.WithLabelValues(grpcType, serviceName, methodName).Inc()

		startTime := time.Now()
		err := handler(srv, ss)
		elapsed := time.Since(startTime).Seconds()

		code := status.Code(err).String()
		ServerHandledTotal.WithLabelValues(grpcType, serviceName, methodName, code).Inc()
		ServerHandlingSeconds.WithLabelValues(grpcType, serviceName, methodName).Observe(elapsed)

		return err
	}
}
