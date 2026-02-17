// Package mtls_test provides unit tests for the mtls config.
package mtls_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/grpc-example/internal/auth/mtls"
)

func TestConfig_IsRestricted(t *testing.T) {
	tests := []struct {
		name string
		cfg  mtls.Config
		want bool
	}{
		{
			name: "no restrictions - empty config",
			cfg:  mtls.Config{},
			want: false,
		},
		{
			name: "no restrictions - nil slices",
			cfg: mtls.Config{
				AllowedSubjects: nil,
				AllowedSANs:     nil,
				AllowedOUs:      nil,
			},
			want: false,
		},
		{
			name: "no restrictions - empty slices",
			cfg: mtls.Config{
				AllowedSubjects: []string{},
				AllowedSANs:     []string{},
				AllowedOUs:      []string{},
			},
			want: false,
		},
		{
			name: "restricted by subjects",
			cfg: mtls.Config{
				AllowedSubjects: []string{"client1"},
			},
			want: true,
		},
		{
			name: "restricted by SANs",
			cfg: mtls.Config{
				AllowedSANs: []string{"client1.example.com"},
			},
			want: true,
		},
		{
			name: "restricted by OUs",
			cfg: mtls.Config{
				AllowedOUs: []string{"Engineering"},
			},
			want: true,
		},
		{
			name: "restricted by all",
			cfg: mtls.Config{
				AllowedSubjects: []string{"client1"},
				AllowedSANs:     []string{"client1.example.com"},
				AllowedOUs:      []string{"Engineering"},
			},
			want: true,
		},
		{
			name: "restricted by subjects and SANs only",
			cfg: mtls.Config{
				AllowedSubjects: []string{"client1", "client2"},
				AllowedSANs:     []string{"client1.example.com"},
				AllowedOUs:      []string{},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			result := tt.cfg.IsRestricted()

			// Assert
			assert.Equal(t, tt.want, result)
		})
	}
}
