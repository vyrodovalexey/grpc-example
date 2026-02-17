package oidc

import (
	"context"
	"fmt"
	"math"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/grpc-example/internal/config"
)

const (
	providerMaxRetries     = 5
	providerBaseRetryDelay = 500 * time.Millisecond
	providerMaxRetryDelay  = 30 * time.Second
)

// Provider defines the interface for OIDC provider operations.
type Provider interface {
	// Verifier returns the OIDC ID token verifier.
	Verifier() TokenVerifier
}

// TokenVerifier defines the interface for verifying OIDC tokens.
type TokenVerifier interface {
	// Verify verifies the raw ID token string and returns the parsed token.
	Verify(ctx context.Context, rawIDToken string) (*gooidc.IDToken, error)
}

// oidcProvider implements the Provider interface using go-oidc.
type oidcProvider struct {
	provider *gooidc.Provider
	verifier TokenVerifier
	logger   *zap.Logger
}

// NewProvider creates a new OIDC provider with discovery and JWKS caching.
// It retries the discovery request with exponential backoff.
func NewProvider(ctx context.Context, cfg config.AuthConfig, logger *zap.Logger) (Provider, error) {
	log := logger.Named("oidc_provider")

	var provider *gooidc.Provider
	var err error

	for attempt := range providerMaxRetries {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled during OIDC discovery: %w", ctx.Err())
		default:
		}

		provider, err = gooidc.NewProvider(ctx, cfg.OIDCIssuerURL)
		if err == nil {
			break
		}

		delay := calculateProviderBackoff(attempt)
		log.Warn("OIDC discovery failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Duration("retry_delay", delay),
			zap.Error(err),
		)

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled during retry wait: %w", ctx.Err())
		case <-time.After(delay):
		}
	}

	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed after %d attempts: %w", providerMaxRetries, err)
	}

	verifierConfig := &gooidc.Config{
		ClientID: cfg.OIDCClientID,
	}

	log.Info("OIDC provider initialized",
		zap.String("issuer", cfg.OIDCIssuerURL),
		zap.String("client_id", cfg.OIDCClientID),
	)

	return &oidcProvider{
		provider: provider,
		verifier: provider.Verifier(verifierConfig),
		logger:   log,
	}, nil
}

// Verifier returns the OIDC ID token verifier.
func (p *oidcProvider) Verifier() TokenVerifier {
	return p.verifier
}

// calculateProviderBackoff calculates exponential backoff delay with a maximum cap.
func calculateProviderBackoff(attempt int) time.Duration {
	delay := providerBaseRetryDelay * time.Duration(math.Pow(2, float64(attempt)))
	if delay > providerMaxRetryDelay {
		delay = providerMaxRetryDelay
	}
	return delay
}
