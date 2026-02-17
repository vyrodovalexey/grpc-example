// Package auth provides common authentication interfaces and types for the gRPC server.
package auth

import (
	"context"
	"fmt"
	"strings"
)

// Authenticator defines the interface for authentication mechanisms.
type Authenticator interface {
	// Authenticate validates the request context and returns an enriched context with identity.
	Authenticate(ctx context.Context) (context.Context, error)
}

// Identity holds information about an authenticated entity.
type Identity struct {
	Subject    string
	Issuer     string
	AuthMethod string
	Claims     map[string]string
}

// String returns a human-readable representation of the identity.
func (i *Identity) String() string {
	if i == nil {
		return "Identity{nil}"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Identity{Subject: %s, Issuer: %s, AuthMethod: %s", i.Subject, i.Issuer, i.AuthMethod))

	if len(i.Claims) > 0 {
		sb.WriteString(", Claims: {")
		first := true
		for k, v := range i.Claims {
			if !first {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%s: %s", k, v))
			first = false
		}
		sb.WriteString("}")
	}

	sb.WriteString("}")
	return sb.String()
}
