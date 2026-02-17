package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/grpc-example/internal/auth"
	"github.com/vyrodovalexey/grpc-example/internal/config"
)

// ValidateToken extracts and validates a bearer token from gRPC metadata.
// Returns an Identity on success or an error if validation fails.
func ValidateToken(
	ctx context.Context,
	provider Provider,
	cfg config.AuthConfig,
) (*auth.Identity, error) {
	token, err := extractBearerToken(ctx)
	if err != nil {
		return nil, err
	}

	idToken, err := provider.Verifier().Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Extract claims.
	var claims map[string]any
	if claimErr := idToken.Claims(&claims); claimErr != nil {
		return nil, fmt.Errorf("extracting token claims: %w", claimErr)
	}

	// Validate audience if configured.
	if cfg.OIDCAudience != "" && !containsAudience(idToken.Audience, cfg.OIDCAudience) {
		return nil, fmt.Errorf(
			"token audience %v does not contain required audience %q",
			idToken.Audience, cfg.OIDCAudience,
		)
	}

	// Build string claims map for Identity.
	stringClaims := make(map[string]string)
	for k, v := range claims {
		stringClaims[k] = fmt.Sprintf("%v", v)
	}

	identity := &auth.Identity{
		Subject:    idToken.Subject,
		Issuer:     idToken.Issuer,
		AuthMethod: "oidc",
		Claims:     stringClaims,
	}

	return identity, nil
}

// extractBearerToken extracts the bearer token from gRPC metadata.
func extractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no metadata in context")
	}

	authValues := md.Get(AuthorizationKey)
	if len(authValues) == 0 {
		return "", fmt.Errorf("no authorization metadata")
	}

	authHeader := authValues[0]
	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return "", fmt.Errorf("authorization header does not have Bearer prefix")
	}

	token := strings.TrimPrefix(authHeader, BearerPrefix)
	if token == "" {
		return "", fmt.Errorf("empty bearer token")
	}

	return token, nil
}

// containsAudience checks if the audience list contains the required audience.
func containsAudience(audiences []string, required string) bool {
	for _, aud := range audiences {
		if aud == required {
			return true
		}
	}
	return false
}

// ValidateRequiredClaims validates that the token claims contain all required claims.
func ValidateRequiredClaims(claims map[string]string, required map[string]string) error {
	for key, expectedValue := range required {
		actualValue, exists := claims[key]
		if !exists {
			return fmt.Errorf("required claim %q not found in token", key)
		}

		// For JSON array values, check if the expected value is contained.
		if isJSONArray(actualValue) {
			if !jsonArrayContains(actualValue, expectedValue) {
				return fmt.Errorf("required claim %q value %q not found in %s", key, expectedValue, actualValue)
			}
			continue
		}

		if actualValue != expectedValue {
			return fmt.Errorf("required claim %q: expected %q, got %q", key, expectedValue, actualValue)
		}
	}
	return nil
}

// isJSONArray checks if a string looks like a JSON array.
func isJSONArray(s string) bool {
	return strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")
}

// jsonArrayContains checks if a JSON array string contains a specific value.
func jsonArrayContains(arrayStr, value string) bool {
	var arr []any
	if err := json.Unmarshal([]byte(arrayStr), &arr); err != nil {
		return false
	}
	for _, item := range arr {
		if fmt.Sprintf("%v", item) == value {
			return true
		}
	}
	return false
}
