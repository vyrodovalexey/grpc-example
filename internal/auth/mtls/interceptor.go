// Package mtls provides mTLS authentication for gRPC servers.
package mtls

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
)

// UnaryInterceptor returns a gRPC unary server interceptor that validates client certificates.
func UnaryInterceptor(cfg Config, logger *zap.Logger) grpc.UnaryServerInterceptor {
	log := logger.Named("mtls_auth")

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		identity, err := ValidatePeerCertificate(ctx, cfg)
		if err != nil {
			log.Warn("mTLS authentication failed",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
			return nil, status.Errorf(codes.Unauthenticated, "mTLS authentication failed: %v", err)
		}

		log.Debug("mTLS authentication successful",
			zap.String("method", info.FullMethod),
			zap.String("subject", identity.Subject),
			zap.String("issuer", identity.Issuer),
		)

		ctx = auth.WithIdentity(ctx, identity)
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC stream server interceptor that validates client certificates.
func StreamInterceptor(cfg Config, logger *zap.Logger) grpc.StreamServerInterceptor {
	log := logger.Named("mtls_auth")

	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		identity, err := ValidatePeerCertificate(ss.Context(), cfg)
		if err != nil {
			log.Warn("mTLS stream authentication failed",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
			return status.Errorf(codes.Unauthenticated, "mTLS authentication failed: %v", err)
		}

		log.Debug("mTLS stream authentication successful",
			zap.String("method", info.FullMethod),
			zap.String("subject", identity.Subject),
			zap.String("issuer", identity.Issuer),
		)

		wrapped := auth.NewAuthenticatedServerStream(ss, auth.WithIdentity(ss.Context(), identity))

		return handler(srv, wrapped)
	}
}
