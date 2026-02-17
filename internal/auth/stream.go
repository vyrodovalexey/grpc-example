package auth

import (
	"context"

	"google.golang.org/grpc"
)

// AuthenticatedServerStream wraps a grpc.ServerStream with an enriched context
// containing authentication identity.
type AuthenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// NewAuthenticatedServerStream creates a new AuthenticatedServerStream wrapping the given
// grpc.ServerStream with an enriched context containing authentication identity.
func NewAuthenticatedServerStream(ss grpc.ServerStream, ctx context.Context) *AuthenticatedServerStream {
	return &AuthenticatedServerStream{
		ServerStream: ss,
		ctx:          ctx,
	}
}

// Context returns the enriched context with the authenticated identity.
func (s *AuthenticatedServerStream) Context() context.Context {
	return s.ctx
}
