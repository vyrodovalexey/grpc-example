package mtls

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
	"github.com/vyrodovalexey/grpc-example/internal/config"
)

// ValidatePeerCertificate extracts and validates the peer certificate from the gRPC context.
// Returns an Identity on success or an error if validation fails.
func ValidatePeerCertificate(ctx context.Context, cfg Config) (*auth.Identity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer info in context")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("peer does not have TLS info")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("no verified client certificate")
	}

	peerCert := tlsInfo.State.VerifiedChains[0][0]

	// If no restrictions are configured, allow all authenticated clients.
	if !cfg.IsRestricted() {
		return buildIdentity(peerCert), nil
	}

	// Validate against allowed subjects.
	if len(cfg.AllowedSubjects) > 0 && !slices.Contains(cfg.AllowedSubjects, peerCert.Subject.CommonName) {
		return nil, fmt.Errorf("client subject %q not in allowed subjects", peerCert.Subject.CommonName)
	}

	// Validate against allowed SANs.
	if len(cfg.AllowedSANs) > 0 && !slices.ContainsFunc(peerCert.DNSNames, func(san string) bool {
		return slices.Contains(cfg.AllowedSANs, san)
	}) {
		return nil, fmt.Errorf("client SANs do not match allowed SANs")
	}

	// Validate against allowed OUs.
	if len(cfg.AllowedOUs) > 0 && !slices.ContainsFunc(peerCert.Subject.OrganizationalUnit, func(ou string) bool {
		return slices.Contains(cfg.AllowedOUs, ou)
	}) {
		return nil, fmt.Errorf("client OU not in allowed OUs")
	}

	return buildIdentity(peerCert), nil
}

// buildIdentity constructs an auth.Identity from a verified peer certificate.
func buildIdentity(peerCert *x509.Certificate) *auth.Identity {
	identity := &auth.Identity{
		Subject:    peerCert.Subject.CommonName,
		Issuer:     peerCert.Issuer.CommonName,
		AuthMethod: config.AuthModeMTLS,
		Claims:     make(map[string]string),
	}

	// Add certificate details to claims.
	if len(peerCert.Subject.Organization) > 0 {
		identity.Claims["org"] = peerCert.Subject.Organization[0]
	}
	if len(peerCert.Subject.OrganizationalUnit) > 0 {
		identity.Claims["ou"] = peerCert.Subject.OrganizationalUnit[0]
	}
	identity.Claims["serial"] = peerCert.SerialNumber.String()

	return identity
}
