// Package mtls provides mTLS authentication for gRPC servers.
package mtls

// Config holds mTLS-specific authentication configuration.
// When all fields are empty, all authenticated clients are allowed.
type Config struct {
	// AllowedSubjects restricts access to clients with matching certificate subjects (CN).
	AllowedSubjects []string
	// AllowedSANs restricts access to clients with matching Subject Alternative Names.
	AllowedSANs []string
	// AllowedOUs restricts access to clients with matching Organizational Units.
	AllowedOUs []string
}

// IsRestricted returns true if any restriction is configured.
func (c *Config) IsRestricted() bool {
	return len(c.AllowedSubjects) > 0 || len(c.AllowedSANs) > 0 || len(c.AllowedOUs) > 0
}
