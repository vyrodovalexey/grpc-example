package mtls

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
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

	// Validate against allowed subjects.
	if len(cfg.AllowedSubjects) > 0 && !containsString(cfg.AllowedSubjects, peerCert.Subject.CommonName) {
		return nil, fmt.Errorf("client subject %q not in allowed subjects", peerCert.Subject.CommonName)
	}

	// Validate against allowed SANs.
	if len(cfg.AllowedSANs) > 0 && !hasMatchingSAN(cfg.AllowedSANs, peerCert.DNSNames) {
		return nil, fmt.Errorf("client SANs do not match allowed SANs")
	}

	// Validate against allowed OUs.
	if len(cfg.AllowedOUs) > 0 && !hasMatchingOU(cfg.AllowedOUs, peerCert.Subject.OrganizationalUnit) {
		return nil, fmt.Errorf("client OU not in allowed OUs")
	}

	identity := &auth.Identity{
		Subject:    peerCert.Subject.CommonName,
		Issuer:     peerCert.Issuer.CommonName,
		AuthMethod: "mtls",
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

	return identity, nil
}

// containsString checks if a string slice contains a specific string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// hasMatchingSAN checks if any of the peer's DNS names match the allowed SANs.
func hasMatchingSAN(allowed, peerSANs []string) bool {
	for _, san := range peerSANs {
		if containsString(allowed, san) {
			return true
		}
	}
	return false
}

// hasMatchingOU checks if any of the peer's OUs match the allowed OUs.
func hasMatchingOU(allowed, peerOUs []string) bool {
	for _, ou := range peerOUs {
		if containsString(allowed, ou) {
			return true
		}
	}
	return false
}
