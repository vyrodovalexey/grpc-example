// Package oidc_test provides unit tests for the oidc validator.
package oidc_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/grpc-example/internal/auth/oidc"
	"github.com/vyrodovalexey/grpc-example/internal/config"
)

// mockTokenVerifier implements oidc.TokenVerifier for testing.
type mockTokenVerifier struct {
	token *gooidc.IDToken
	err   error
}

func (m *mockTokenVerifier) Verify(_ context.Context, _ string) (*gooidc.IDToken, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

// mockProvider implements oidc.Provider for testing.
type mockProvider struct {
	verifier oidc.TokenVerifier
}

func (m *mockProvider) Verifier() oidc.TokenVerifier {
	return m.verifier
}

func (m *mockProvider) Healthy(_ context.Context) bool {
	return true
}

// setIDTokenClaims sets the unexported claims field on an IDToken for testing.
func setIDTokenClaims(token *gooidc.IDToken, claimsJSON []byte) {
	v := reflect.ValueOf(token).Elem()
	f := v.FieldByName("claims")
	// Use unsafe to set unexported field.
	ptr := unsafe.Pointer(f.UnsafeAddr()) //nolint:gosec // test-only
	*(*[]byte)(ptr) = claimsJSON
}

// createIDTokenWithClaims creates an IDToken with claims set for testing.
func createIDTokenWithClaims(issuer, subject string, audience []string, claimsJSON string) *gooidc.IDToken {
	token := &gooidc.IDToken{
		Issuer:   issuer,
		Subject:  subject,
		Audience: audience,
	}
	setIDTokenClaims(token, []byte(claimsJSON))
	return token
}

// createIncomingContext creates a context with gRPC incoming metadata.
func createIncomingContext(key, value string) context.Context {
	md := metadata.New(map[string]string{key: value})
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		provider    oidc.Provider
		cfg         config.AuthConfig
		wantErr     bool
		errContains string
		wantSubject string
	}{
		{
			name: "valid token - no audience check",
			ctx:  createIncomingContext("authorization", "Bearer valid-token"),
			provider: &mockProvider{
				verifier: &mockTokenVerifier{
					token: createIDTokenWithClaims(
						"https://issuer.example.com",
						"user@example.com",
						[]string{"test-client"},
						`{"sub":"user@example.com","iss":"https://issuer.example.com"}`,
					),
				},
			},
			cfg:         config.AuthConfig{},
			wantErr:     false,
			wantSubject: "user@example.com",
		},
		{
			name: "valid token - audience matches",
			ctx:  createIncomingContext("authorization", "Bearer valid-token"),
			provider: &mockProvider{
				verifier: &mockTokenVerifier{
					token: createIDTokenWithClaims(
						"https://issuer.example.com",
						"user@example.com",
						[]string{"test-client", "other-client"},
						`{"sub":"user@example.com"}`,
					),
				},
			},
			cfg: config.AuthConfig{
				OIDCAudience: "test-client",
			},
			wantErr:     false,
			wantSubject: "user@example.com",
		},
		{
			name: "audience mismatch",
			ctx:  createIncomingContext("authorization", "Bearer valid-token"),
			provider: &mockProvider{
				verifier: &mockTokenVerifier{
					token: createIDTokenWithClaims(
						"https://issuer.example.com",
						"user@example.com",
						[]string{"other-client"},
						`{"sub":"user@example.com"}`,
					),
				},
			},
			cfg: config.AuthConfig{
				OIDCAudience: "test-client",
			},
			wantErr:     true,
			errContains: "does not contain required audience",
		},
		{
			name:        "no metadata in context",
			ctx:         context.Background(),
			provider:    &mockProvider{verifier: &mockTokenVerifier{}},
			cfg:         config.AuthConfig{},
			wantErr:     true,
			errContains: "no metadata in context",
		},
		{
			name: "no authorization header",
			ctx: func() context.Context {
				md := metadata.New(map[string]string{"other-key": "value"})
				return metadata.NewIncomingContext(context.Background(), md)
			}(),
			provider:    &mockProvider{verifier: &mockTokenVerifier{}},
			cfg:         config.AuthConfig{},
			wantErr:     true,
			errContains: "no authorization metadata",
		},
		{
			name:        "authorization without Bearer prefix",
			ctx:         createIncomingContext("authorization", "Basic dXNlcjpwYXNz"),
			provider:    &mockProvider{verifier: &mockTokenVerifier{}},
			cfg:         config.AuthConfig{},
			wantErr:     true,
			errContains: "does not have Bearer prefix",
		},
		{
			name:        "empty bearer token",
			ctx:         createIncomingContext("authorization", "Bearer "),
			provider:    &mockProvider{verifier: &mockTokenVerifier{}},
			cfg:         config.AuthConfig{},
			wantErr:     true,
			errContains: "empty bearer token",
		},
		{
			name: "token verification failure",
			ctx:  createIncomingContext("authorization", "Bearer invalid-token"),
			provider: &mockProvider{
				verifier: &mockTokenVerifier{
					err: fmt.Errorf("token expired"),
				},
			},
			cfg:         config.AuthConfig{},
			wantErr:     true,
			errContains: "token verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			identity, err := oidc.ValidateToken(tt.ctx, tt.provider, tt.cfg)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, identity)
			} else {
				require.NoError(t, err)
				require.NotNil(t, identity)
				assert.Equal(t, tt.wantSubject, identity.Subject)
				assert.Equal(t, "oidc", identity.AuthMethod)
			}
		})
	}
}

func TestValidateRequiredClaims(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]string
		required    map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name:     "no required claims",
			claims:   map[string]string{"role": "admin"},
			required: map[string]string{},
			wantErr:  false,
		},
		{
			name:     "nil required claims",
			claims:   map[string]string{"role": "admin"},
			required: nil,
			wantErr:  false,
		},
		{
			name:     "matching claim",
			claims:   map[string]string{"role": "admin"},
			required: map[string]string{"role": "admin"},
			wantErr:  false,
		},
		{
			name:     "multiple matching claims",
			claims:   map[string]string{"role": "admin", "scope": "read"},
			required: map[string]string{"role": "admin", "scope": "read"},
			wantErr:  false,
		},
		{
			name:        "missing required claim",
			claims:      map[string]string{"role": "admin"},
			required:    map[string]string{"scope": "read"},
			wantErr:     true,
			errContains: "required claim \"scope\" not found",
		},
		{
			name:        "claim value mismatch",
			claims:      map[string]string{"role": "user"},
			required:    map[string]string{"role": "admin"},
			wantErr:     true,
			errContains: "expected \"admin\", got \"user\"",
		},
		{
			name:     "JSON array claim - value found",
			claims:   map[string]string{"roles": `["admin","user","viewer"]`},
			required: map[string]string{"roles": "admin"},
			wantErr:  false,
		},
		{
			name:        "JSON array claim - value not found",
			claims:      map[string]string{"roles": `["user","viewer"]`},
			required:    map[string]string{"roles": "admin"},
			wantErr:     true,
			errContains: "not found in",
		},
		{
			name:        "invalid JSON array - falls through to string comparison",
			claims:      map[string]string{"roles": `[invalid json`},
			required:    map[string]string{"roles": "admin"},
			wantErr:     true,
			errContains: "expected \"admin\"",
		},
		{
			name:     "empty claims with no requirements",
			claims:   map[string]string{},
			required: map[string]string{},
			wantErr:  false,
		},
		{
			name:        "empty claims with requirements",
			claims:      map[string]string{},
			required:    map[string]string{"role": "admin"},
			wantErr:     true,
			errContains: "not found in token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			err := oidc.ValidateRequiredClaims(tt.claims, tt.required)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
