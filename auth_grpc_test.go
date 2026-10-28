package main

import (
	"strings"
	"testing"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

// The agent sends plugin config over gRPC as a flat map<string, string>; the plugin decodes it
// into PluginConfig on its side. These tests send Configure through a real go-plugin gRPC
// connection, so they cover the embedded (squashed) AuthConfig the way the agent uses it.
func configureOverGRPC(t *testing.T, config map[string]string) (*GithubReposPlugin, error) {
	t.Helper()
	impl := &GithubReposPlugin{Logger: hclog.NewNullLogger()}
	client, _ := goplugin.TestPluginGRPCConn(t, false, map[string]goplugin.Plugin{
		"runner": &runner.RunnerV2GRPCPlugin{Impl: impl},
	})
	t.Cleanup(func() { _ = client.Close() })

	raw, err := client.Dispense("runner")
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.(runner.Runner).Configure(&proto.ConfigureRequest{Config: config})
	return impl, err
}

func TestConfigureOverGRPCWithToken(t *testing.T) {
	// The config every existing deployment sends.
	impl, err := configureOverGRPC(t, map[string]string{"token": "ghp_abc", "organization": "octocat"})
	if err != nil {
		t.Fatal(err)
	}
	if impl.config.Token != "ghp_abc" || impl.githubClient == nil || impl.graphqlClient == nil {
		t.Fatalf("token config not applied: token=%q", impl.config.Token)
	}
}

func TestConfigureOverGRPCWithGitHubApp(t *testing.T) {
	impl, err := configureOverGRPC(t, map[string]string{
		"app_id":          "1",
		"installation_id": "2",
		"private_key":     string(testPrivateKey(t)),
		"organization":    "octocat",
		// Empty keys, as agent configs declare them for environment injection.
		"token":            "",
		"private_key_file": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if impl.config.AppID != "1" || impl.config.InstallationID != "2" || impl.githubClient == nil {
		t.Fatalf("app config not applied: %+v", impl.config.AuthConfig)
	}
}

func TestConfigureOverGRPCRejectsIncompleteApp(t *testing.T) {
	_, err := configureOverGRPC(t, map[string]string{"app_id": "1", "organization": "octocat"})
	if err == nil || !strings.Contains(err.Error(), "installation_id") {
		t.Fatalf("error = %v, want one naming installation_id", err)
	}
}
