// Package auth provides common authentication interfaces and types for the gRPC server.
package auth

import "context"

// contextKey is an unexported type for context keys to prevent collisions.
type contextKey struct{}

// identityKey is the context key for storing the authenticated identity.
var identityKey = contextKey{}

// WithIdentity returns a new context with the given identity stored.
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}

// IdentityFromContext retrieves the authenticated identity from the context.
// Returns nil and false if no identity is present.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	identity, ok := ctx.Value(identityKey).(*Identity)
	return identity, ok
}
