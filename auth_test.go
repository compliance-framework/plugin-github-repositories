package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
)

func testPrivateKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func TestAuthConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AuthConfig
		wantErr string
	}{
		{name: "token", cfg: AuthConfig{Token: "ghp_abc"}},
		{name: "token wins over partial app credentials", cfg: AuthConfig{Token: "ghp_abc", AppID: "1"}},
		{name: "app with key file", cfg: AuthConfig{AppID: "1", InstallationID: "2", PrivateKeyFile: "/key.pem"}},
		{name: "app with inline key", cfg: AuthConfig{AppID: "1", InstallationID: "2", PrivateKey: "abc"}},
		{name: "nothing", cfg: AuthConfig{}, wantErr: "token or GitHub App credentials"},
		{name: "app without installation", cfg: AuthConfig{AppID: "1", PrivateKey: "abc"}, wantErr: "needs installation_id"},
		{name: "app without key", cfg: AuthConfig{AppID: "1", InstallationID: "2"}, wantErr: "needs private_key_file or private_key"},
		{name: "two keys", cfg: AuthConfig{AppID: "1", InstallationID: "2", PrivateKeyFile: "/key.pem", PrivateKey: "abc"}, wantErr: "only one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validateAuth()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuthConfigHTTPClient(t *testing.T) {
	pemKey := testPrivateKey(t)
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyFile, pemKey, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("token", func(t *testing.T) {
		c, err := (&AuthConfig{Token: "ghp_abc"}).httpClient(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := c.Transport.(*oauth2.Transport); !ok {
			t.Fatalf("transport = %T, want *oauth2.Transport", c.Transport)
		}
	})

	for name, cfg := range map[string]AuthConfig{
		"app with key file":      {AppID: "1", InstallationID: "2", PrivateKeyFile: keyFile},
		"app with base64 key":    {AppID: "1", InstallationID: "2", PrivateKey: base64.StdEncoding.EncodeToString(pemKey)},
		"app with plain PEM key": {AppID: "1", InstallationID: "2", PrivateKey: string(pemKey)},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := cfg.httpClient(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			tr, ok := c.Transport.(*ghinstallation.Transport)
			if !ok {
				t.Fatalf("transport = %T, want *ghinstallation.Transport", c.Transport)
			}
			if tr.AppID() != 1 || tr.InstallationID() != 2 {
				t.Fatalf("app %d installation %d, want 1 and 2", tr.AppID(), tr.InstallationID())
			}
		})
	}

	for name, cfg := range map[string]AuthConfig{
		"non-numeric app_id":   {AppID: "abc", InstallationID: "2", PrivateKey: string(pemKey)},
		"missing key file":     {AppID: "1", InstallationID: "2", PrivateKeyFile: filepath.Join(t.TempDir(), "nope.pem")},
		"key is not base64":    {AppID: "1", InstallationID: "2", PrivateKey: "not base64!"},
		"key is not a PEM key": {AppID: "1", InstallationID: "2", PrivateKey: base64.StdEncoding.EncodeToString([]byte("nope"))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := cfg.httpClient(context.Background()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// The agent passes plugin config as a flat map; the auth keys must land in the embedded struct.
func TestPluginConfigDecodesAuthKeys(t *testing.T) {
	var cfg PluginConfig
	err := mapstructure.Decode(map[string]string{
		"app_id": "1", "installation_id": "2", "private_key_file": "/key.pem", "organization": "octocat",
	}, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppID != "1" || cfg.InstallationID != "2" || cfg.PrivateKeyFile != "/key.pem" {
		t.Fatalf("auth keys not decoded: %+v", cfg.AuthConfig)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
