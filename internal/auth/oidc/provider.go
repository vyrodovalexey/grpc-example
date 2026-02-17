// Package oidc provides OIDC (OpenID Connect) authentication for gRPC servers.
package oidc

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/config"
	"github.com/vyrodovalexey/grpc-example/internal/retry"
)

const (
	// healthCheckTimeout is the timeout for OIDC health check HTTP requests.
	healthCheckTimeout = 10 * time.Second
	// wellKnownSuffix is the OIDC well-known configuration endpoint path.
	wellKnownSuffix = "/.well-known/openid-configuration"
)

// Provider defines the interface for OIDC provider operations.
type Provider interface {
	// Verifier returns the OIDC ID token verifier.
	Verifier() TokenVerifier
	// Healthy returns true if the OIDC provider is reachable.
	Healthy(ctx context.Context) bool
}

// TokenVerifier defines the interface for verifying OIDC tokens.
type TokenVerifier interface {
	// Verify verifies the raw ID token string and returns the parsed token.
	Verify(ctx context.Context, rawIDToken string) (*gooidc.IDToken, error)
}

// oidcProvider implements the Provider interface using go-oidc.
type oidcProvider struct {
	provider   *gooidc.Provider
	verifier   TokenVerifier
	issuerURL  string
	logger     *zap.Logger
	healthy    atomic.Bool
	httpClient *http.Client
}

// NewProvider creates a new OIDC provider with discovery and JWKS caching.
// It retries the discovery request with exponential backoff.
func NewProvider(ctx context.Context, cfg config.AuthConfig, logger *zap.Logger) (Provider, error) {
	log := logger.Named("oidc_provider")

	var provider *gooidc.Provider

	err := retry.Do(ctx, retry.DefaultConfig(), log, "OIDC discovery", func() error {
		var discoverErr error
		provider, discoverErr = gooidc.NewProvider(ctx, cfg.OIDCIssuerURL)
		return discoverErr
	})
	if err != nil {
		return nil, err
	}

	verifierConfig := &gooidc.Config{
		ClientID: cfg.OIDCClientID,
	}

	log.Info("OIDC provider initialized",
		zap.String("issuer", cfg.OIDCIssuerURL),
		zap.String("client_id", cfg.OIDCClientID),
	)

	p := &oidcProvider{
		provider:  provider,
		verifier:  provider.Verifier(verifierConfig),
		issuerURL: cfg.OIDCIssuerURL,
		logger:    log,
		httpClient: &http.Client{
			Timeout: healthCheckTimeout,
		},
	}
	p.healthy.Store(true)

	return p, nil
}

// Verifier returns the OIDC ID token verifier.
func (p *oidcProvider) Verifier() TokenVerifier {
	return p.verifier
}

// Healthy checks if the OIDC provider is reachable by performing a lightweight HTTP GET
// to the well-known OpenID configuration endpoint.
// This can be used by health check endpoints or circuit breaker patterns.
func (p *oidcProvider) Healthy(ctx context.Context) bool {
	isHealthy := p.checkHealth(ctx)
	wasHealthy := p.healthy.Swap(isHealthy)

	if wasHealthy && !isHealthy {
		p.logger.Warn("OIDC provider became unavailable",
			zap.String("issuer", p.issuerURL),
		)
	} else if !wasHealthy && isHealthy {
		p.logger.Info("OIDC provider recovered",
			zap.String("issuer", p.issuerURL),
		)
	}

	return isHealthy
}

// checkHealth performs a lightweight HTTP GET to the OIDC well-known endpoint.
func (p *oidcProvider) checkHealth(ctx context.Context) bool {
	wellKnownURL := fmt.Sprintf("%s%s", p.issuerURL, wellKnownSuffix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, http.NoBody)
	if err != nil {
		p.logger.Warn("failed to create OIDC health check request",
			zap.String("issuer", p.issuerURL),
			zap.Error(err),
		)
		return false
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.logger.Debug("OIDC health check request failed",
			zap.String("issuer", p.issuerURL),
			zap.Error(err),
		)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
