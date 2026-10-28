package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"golang.org/x/oauth2"
)

// AuthConfig is how the plugin authenticates to GitHub: a token (personal access token or
// any other bearer token) or a GitHub App installation. A token wins when both are set.
type AuthConfig struct {
	Token string `mapstructure:"token"`

	// GitHub App authentication. The plugin exchanges the app's private key for short-lived
	// installation tokens, renewed as they expire.
	AppID          string `mapstructure:"app_id"`
	InstallationID string `mapstructure:"installation_id"`
	// The PEM private key, from a file (preferred: keeps the key out of the config) or inline,
	// base64-encoded or as plain PEM.
	PrivateKeyFile string `mapstructure:"private_key_file"`
	PrivateKey     string `mapstructure:"private_key"`
}

// validateAuth requires a token or a complete set of GitHub App credentials.
func (c *AuthConfig) validateAuth() error {
	if c.Token != "" {
		return nil
	}
	if c.AppID == "" && c.InstallationID == "" && c.PrivateKeyFile == "" && c.PrivateKey == "" {
		return errors.New("token or GitHub App credentials (app_id, installation_id and private_key_file or private_key) are required")
	}
	var missing []string
	if c.AppID == "" {
		missing = append(missing, "app_id")
	}
	if c.InstallationID == "" {
		missing = append(missing, "installation_id")
	}
	if c.PrivateKeyFile == "" && c.PrivateKey == "" {
		missing = append(missing, "private_key_file or private_key")
	}
	if len(missing) > 0 {
		return fmt.Errorf("GitHub App authentication needs %s", strings.Join(missing, ", "))
	}
	if c.PrivateKeyFile != "" && c.PrivateKey != "" {
		return errors.New("only one of private_key_file or private_key may be set")
	}
	return nil
}

// httpClient returns an HTTP client that authenticates every request to GitHub (REST and
// GraphQL alike).
func (c *AuthConfig) httpClient(ctx context.Context) (*http.Client, error) {
	if c.Token != "" {
		return oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: c.Token})), nil
	}

	appID, err := strconv.ParseInt(c.AppID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing app_id: %w", err)
	}
	installationID, err := strconv.ParseInt(c.InstallationID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing installation_id: %w", err)
	}
	key, err := c.privateKey()
	if err != nil {
		return nil, err
	}
	transport, err := ghinstallation.New(http.DefaultTransport, appID, installationID, key)
	if err != nil {
		return nil, fmt.Errorf("creating GitHub App installation transport: %w", err)
	}
	return &http.Client{Transport: transport}, nil
}

func (c *AuthConfig) privateKey() ([]byte, error) {
	if c.PrivateKeyFile != "" {
		key, err := os.ReadFile(c.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading private_key_file: %w", err)
		}
		return key, nil
	}
	key := strings.TrimSpace(c.PrivateKey)
	if strings.HasPrefix(key, "-----BEGIN") {
		return []byte(key), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("decoding private_key (expected PEM or base64-encoded PEM): %w", err)
	}
	return decoded, nil
}
