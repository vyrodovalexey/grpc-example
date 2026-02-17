package oidc

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
	"github.com/vyrodovalexey/grpc-example/internal/config"
)

// UnaryInterceptor returns a gRPC unary server interceptor that validates OIDC bearer tokens.
func UnaryInterceptor(
	provider Provider,
	cfg config.AuthConfig,
	logger *zap.Logger,
) grpc.UnaryServerInterceptor {
	log := logger.Named("oidc_auth")

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		identity, err := ValidateToken(ctx, provider, cfg)
		if err != nil {
			log.Warn("OIDC authentication failed",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
			return nil, status.Errorf(codes.Unauthenticated, "OIDC authentication failed: %v", err)
		}

		log.Debug("OIDC authentication successful",
			zap.String("method", info.FullMethod),
			zap.String("subject", identity.Subject),
			zap.String("issuer", identity.Issuer),
		)

		ctx = auth.WithIdentity(ctx, identity)
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC stream server interceptor that validates OIDC bearer tokens.
func StreamInterceptor(
	provider Provider,
	cfg config.AuthConfig,
	logger *zap.Logger,
) grpc.StreamServerInterceptor {
	log := logger.Named("oidc_auth")

	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		identity, err := ValidateToken(ss.Context(), provider, cfg)
		if err != nil {
			log.Warn("OIDC stream authentication failed",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
			return status.Errorf(codes.Unauthenticated, "OIDC authentication failed: %v", err)
		}

		log.Debug("OIDC stream authentication successful",
			zap.String("method", info.FullMethod),
			zap.String("subject", identity.Subject),
			zap.String("issuer", identity.Issuer),
		)

		wrapped := &authenticatedServerStream{
			ServerStream: ss,
			ctx:          auth.WithIdentity(ss.Context(), identity),
		}

		return handler(srv, wrapped)
	}
}

// authenticatedServerStream wraps a grpc.ServerStream with an enriched context.
type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the enriched context with the authenticated identity.
func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}
