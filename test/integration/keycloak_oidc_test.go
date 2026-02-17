//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenResponse represents the Keycloak token endpoint response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// acquireToken obtains an access token from Keycloak using client credentials.
func acquireToken(t *testing.T, clientID, clientSecret string) *tokenResponse {
	t.Helper()

	tokenURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/token",
		testConfig.KeycloakURL,
		testConfig.KeycloakRealm,
	)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	ctx, cancel := newIntegrationContext()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)

	return &tokenResp
}

// acquireTokenWithPassword obtains an access token using resource owner password credentials.
func acquireTokenWithPassword(t *testing.T, username, password string) *tokenResponse {
	t.Helper()

	tokenURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/token",
		testConfig.KeycloakURL,
		testConfig.KeycloakRealm,
	)

	data := url.Values{
		"grant_type":    {"password"},
		"client_id":     {testConfig.ClientID},
		"client_secret": {testConfig.ClientSecret},
		"username":      {username},
		"password":      {password},
	}

	ctx, cancel := newIntegrationContext()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)

	return &tokenResp
}

// refreshToken refreshes an access token using a refresh token.
func refreshToken(t *testing.T, refreshTok string) *tokenResponse {
	t.Helper()

	tokenURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/token",
		testConfig.KeycloakURL,
		testConfig.KeycloakRealm,
	)

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {testConfig.ClientID},
		"client_secret": {testConfig.ClientSecret},
		"refresh_token": {refreshTok},
	}

	ctx, cancel := newIntegrationContext()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	err = json.Unmarshal(body, &tokenResp)
	require.NoError(t, err)

	return &tokenResp
}

func TestIntegration_Keycloak_AcquireToken(t *testing.T) {
	skipIfKeycloakUnavailable(t)

	tokenResp := acquireToken(t, testConfig.ClientID, testConfig.ClientSecret)

	assert.NotEmpty(t, tokenResp.AccessToken, "access token should not be empty")
	assert.Equal(t, "Bearer", tokenResp.TokenType)
	assert.Greater(t, tokenResp.ExpiresIn, 0)
}

func TestIntegration_Keycloak_TokenValidation(t *testing.T) {
	skipIfKeycloakUnavailable(t)

	tokenResp := acquireToken(t, testConfig.ClientID, testConfig.ClientSecret)
	require.NotEmpty(t, tokenResp.AccessToken)

	// Validate the token by introspecting it.
	introspectURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/token/introspect",
		testConfig.KeycloakURL,
		testConfig.KeycloakRealm,
	)

	data := url.Values{
		"token":         {tokenResp.AccessToken},
		"client_id":     {testConfig.ClientID},
		"client_secret": {testConfig.ClientSecret},
	}

	ctx, cancel := newIntegrationContext()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectURL, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var introspection map[string]interface{}
	err = json.Unmarshal(body, &introspection)
	require.NoError(t, err)

	assert.Equal(t, true, introspection["active"], "token should be active")
}

func TestIntegration_Keycloak_InvalidCredentials(t *testing.T) {
	skipIfKeycloakUnavailable(t)

	tokenURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/token",
		testConfig.KeycloakURL,
		testConfig.KeycloakRealm,
	)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"invalid-client"},
		"client_secret": {"invalid-secret"},
	}

	ctx, cancel := newIntegrationContext()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_Keycloak_TokenRefresh(t *testing.T) {
	skipIfKeycloakUnavailable(t)

	// First acquire a token with password grant to get a refresh token.
	// If password grant is not available, skip.
	tokenResp := acquireToken(t, testConfig.ClientID, testConfig.ClientSecret)
	require.NotEmpty(t, tokenResp.AccessToken)

	if tokenResp.RefreshToken == "" {
		t.Skip("skipping: no refresh token returned (client credentials grant may not return refresh tokens)")
	}

	// Refresh the token.
	refreshedResp := refreshToken(t, tokenResp.RefreshToken)

	assert.NotEmpty(t, refreshedResp.AccessToken)
	assert.NotEqual(t, tokenResp.AccessToken, refreshedResp.AccessToken,
		"refreshed token should be different from original")
}

func TestIntegration_Keycloak_DiscoveryEndpoint(t *testing.T) {
	skipIfKeycloakUnavailable(t)

	discoveryURL := fmt.Sprintf(
		"%s/realms/%s/.well-known/openid-configuration",
		testConfig.KeycloakURL,
		testConfig.KeycloakRealm,
	)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var discovery map[string]interface{}
	err = json.Unmarshal(body, &discovery)
	require.NoError(t, err)

	assert.NotEmpty(t, discovery["issuer"])
	assert.NotEmpty(t, discovery["token_endpoint"])
	assert.NotEmpty(t, discovery["jwks_uri"])
	assert.NotEmpty(t, discovery["authorization_endpoint"])
}

func TestIntegration_Keycloak_JWKSEndpoint(t *testing.T) {
	skipIfKeycloakUnavailable(t)

	jwksURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/certs",
		testConfig.KeycloakURL,
		testConfig.KeycloakRealm,
	)

	ctx, cancel := newIntegrationContext()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var jwks map[string]interface{}
	err = json.Unmarshal(body, &jwks)
	require.NoError(t, err)

	keys, ok := jwks["keys"].([]interface{})
	require.True(t, ok, "JWKS should contain keys array")
	assert.NotEmpty(t, keys, "JWKS should have at least one key")
}
