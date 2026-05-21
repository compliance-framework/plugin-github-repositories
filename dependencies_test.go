package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestParseGoModDirectDependencies(t *testing.T) {
	content := []byte(`module example.com/app

require github.com/single/line v1.0.0

require (
	github.com/direct/lib v1.2.3
	github.com/indirect/lib v0.4.0 // indirect
)
`)

	deps, err := parseGoModDirectDependencies(content)
	if err != nil {
		t.Fatalf("parseGoModDirectDependencies returned error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 direct dependencies, got %d", len(deps))
	}
	if deps[0].Name != "github.com/single/line" || deps[0].Version != "v1.0.0" {
		t.Fatalf("unexpected single-line dependency: %#v", deps[0])
	}
	if deps[1].Name != "github.com/direct/lib" || deps[1].Version != "v1.2.3" {
		t.Fatalf("unexpected block dependency: %#v", deps[1])
	}
}

func TestResolveGitHubModulePath(t *testing.T) {
	owner, repo, ok := resolveGitHubModulePath("github.com/google/go-github/v71")
	if !ok {
		t.Fatal("expected GitHub module path to resolve")
	}
	if owner != "google" || repo != "go-github" {
		t.Fatalf("unexpected resolution: %s/%s", owner, repo)
	}

	_, _, ok = resolveGitHubModulePath("golang.org/x/mod")
	if ok {
		t.Fatal("expected non-GitHub module path not to resolve")
	}
}

func TestDependencyHealthConfigDefaultsAndInvalidValues(t *testing.T) {
	cfg := &PluginConfig{}
	if err := cfg.parseDependencyHealthConfig(); err != nil {
		t.Fatalf("parseDependencyHealthConfig returned error: %v", err)
	}
	if cfg.dependencyHealthEnabled {
		t.Fatal("dependency health should default to disabled")
	}
	if cfg.dependencyHealthMaxDependencies != 50 {
		t.Fatalf("expected max dependencies default 50, got %d", cfg.dependencyHealthMaxDependencies)
	}
	if !cfg.dependencyHealthIncludeUnresolved {
		t.Fatal("include unresolved should default to true")
	}
	if !cfg.dependencyHealthCollectSBOM {
		t.Fatal("collect SBOM should default to true")
	}

	cfg = &PluginConfig{DependencyHealthMaxDependencies: "0"}
	if err := cfg.parseDependencyHealthConfig(); err == nil {
		t.Fatal("expected invalid max dependencies to fail")
	}

	cfg = &PluginConfig{DependencyHealthEnabled: "not-bool"}
	if err := cfg.parseDependencyHealthConfig(); err == nil {
		t.Fatal("expected invalid bool to fail")
	}
}

func TestConfigureDefaultsPolicyData(t *testing.T) {
	plugin := &GithubReposPlugin{Logger: hclog.NewNullLogger()}
	_, err := plugin.Configure(&proto.ConfigureRequest{
		Config: map[string]string{
			"token":        "test-token",
			"organization": "test-org",
		},
	})
	if err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if plugin.config.policyData == nil {
		t.Fatal("expected policy data to default to an empty map")
	}
	if len(plugin.config.policyData) != 0 {
		t.Fatalf("expected empty policy data, got %#v", plugin.config.policyData)
	}
}

func TestConfigureLegacyPolicyInputFallback(t *testing.T) {
	plugin := &GithubReposPlugin{Logger: hclog.NewNullLogger()}
	_, err := plugin.Configure(&proto.ConfigureRequest{
		Config: map[string]string{
			"token":        "test-token",
			"organization": "test-org",
			"policy_input": `{"workflow_names":["ci.yml"],"enabled":true}`,
		},
	})
	if err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if got := plugin.config.policyData["enabled"]; got != true {
		t.Fatalf("expected legacy policy_input to populate policy data, got %#v", got)
	}
	workflowNames, ok := plugin.config.policyData["workflow_names"].([]interface{})
	if !ok || len(workflowNames) != 1 || workflowNames[0] != "ci.yml" {
		t.Fatalf("unexpected workflow_names from legacy policy_input: %#v", plugin.config.policyData["workflow_names"])
	}
}

func TestConfigurePolicyDataOverridesLegacyPolicyInput(t *testing.T) {
	plugin := &GithubReposPlugin{Logger: hclog.NewNullLogger()}
	policyData, err := structpb.NewStruct(map[string]interface{}{
		"source": "request",
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	_, err = plugin.Configure(&proto.ConfigureRequest{
		Config: map[string]string{
			"token":        "test-token",
			"organization": "test-org",
			"policy_input": `{"source":"legacy"}`,
		},
		PolicyData: policyData,
	})
	if err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if got := plugin.config.policyData["source"]; got != "request" {
		t.Fatalf("expected request policy_data to win, got %#v", got)
	}
}

func TestConfigureInvalidLegacyPolicyInputFails(t *testing.T) {
	plugin := &GithubReposPlugin{Logger: hclog.NewNullLogger()}
	_, err := plugin.Configure(&proto.ConfigureRequest{
		Config: map[string]string{
			"token":        "test-token",
			"organization": "test-org",
			"policy_input": `not-json`,
		},
	})
	if err == nil {
		t.Fatal("expected invalid legacy policy_input to fail")
	}
}

func TestSaturatedRepositoryPolicyInputAlias(t *testing.T) {
	repo := &SaturatedRepository{
		PolicyData: map[string]interface{}{"source": "policy-data"},
	}
	plugin := &GithubReposPlugin{Logger: hclog.NewNullLogger()}
	_, err := plugin.EvaluatePolicies(t.Context(), repo, nil, nil, nil)
	if err != nil {
		t.Fatalf("EvaluatePolicies returned error: %v", err)
	}
	if repo.PolicyInput["source"] != "policy-data" {
		t.Fatalf("expected policy_input alias to match policy_data, got %#v", repo.PolicyInput)
	}
}

func TestSaturatedRepositoryPolicyInputAliasMarshalsWhenEmpty(t *testing.T) {
	repo := &SaturatedRepository{
		PolicyData:  map[string]interface{}{},
		PolicyInput: map[string]interface{}{},
	}
	payload, err := json.Marshal(repo)
	if err != nil {
		t.Fatalf("failed to marshal repository: %v", err)
	}
	if !strings.Contains(string(payload), `"policy_input":{}`) {
		t.Fatalf("expected empty policy_input to be present, got %s", payload)
	}
}

func TestMedianHelpers(t *testing.T) {
	prs := []*github.Issue{
		{
			CreatedAt: githubTimestamp("2026-01-01T00:00:00Z"),
			ClosedAt:  githubTimestamp("2026-01-03T00:00:00Z"),
		},
		{
			CreatedAt: githubTimestamp("2026-01-01T00:00:00Z"),
			ClosedAt:  githubTimestamp("2026-01-05T00:00:00Z"),
		},
	}
	median := medianDaysToClose(prs)
	if median == nil || *median != 3 {
		t.Fatalf("expected median close time 3 days, got %v", median)
	}

	values := []float64{10, 2, 4}
	got := medianFloat64(values)
	if got == nil || *got != 4 {
		t.Fatalf("expected median 4, got %v", got)
	}
}

func TestRequestWithDefaultPolicyBehaviorClassifiesAllPolicyPaths(t *testing.T) {
	req := &proto.EvalRequest{
		PolicyPaths: []string{
			"ghcr.io/compliance-framework/plugin-github-repositories-policies:v0.6.1",
			"/policies/plugin-github-repositories-dependency-policies.tar.gz",
			"/policies/custom-github-repository-policies.tar.gz",
		},
	}

	policyRequest := requestWithDefaultPolicyBehavior(req)

	assertStringSlicesEqual(t, policyRequest.PolicyPathsForBehavior(policyBehaviorRepository), []string{
		"ghcr.io/compliance-framework/plugin-github-repositories-policies:v0.6.1",
		"/policies/custom-github-repository-policies.tar.gz",
	})
	assertStringSlicesEqual(t, policyRequest.PolicyPathsForBehavior(policyBehaviorDependency), []string{
		"/policies/plugin-github-repositories-dependency-policies.tar.gz",
	})
}

func TestGatherRepositoryDependenciesEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	goMod := `module github.com/source/target

require (
	github.com/good/lib v1.2.3
	github.com/good/lib/submodule v1.2.4
	github.com/quiet/lib v0.9.0
	example.com/unresolved/lib v0.1.0
	github.com/indirect/lib v0.4.0 // indirect
)
`
	goodRepoGetCount := 0
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/source/target/contents/go.mod":
			writeJSON(t, w, map[string]any{
				"type":     "file",
				"name":     "go.mod",
				"path":     "go.mod",
				"encoding": "base64",
				"content":  base64.StdEncoding.EncodeToString([]byte(goMod)),
			})
		case r.URL.Path == "/repos/good/lib":
			goodRepoGetCount++
			writeJSON(t, w, map[string]any{
				"name":           "lib",
				"full_name":      "good/lib",
				"default_branch": "main",
				"archived":       false,
			})
		case r.URL.Path == "/repos/quiet/lib":
			writeJSON(t, w, map[string]any{
				"name":           "lib",
				"full_name":      "quiet/lib",
				"default_branch": "main",
				"archived":       true,
			})
		case r.URL.Path == "/repos/good/lib/releases/latest":
			writeJSON(t, w, map[string]any{
				"tag_name":     "v1.3.0",
				"published_at": "2026-01-10T00:00:00Z",
			})
		case r.URL.Path == "/repos/quiet/lib/releases/latest":
			http.NotFound(w, r)
		case r.URL.Path == "/repos/good/lib/commits":
			writeJSON(t, w, []map[string]any{{
				"sha": "abc123",
				"commit": map[string]any{
					"committer": map[string]any{"date": "2026-02-01T00:00:00Z"},
				},
			}})
		case r.URL.Path == "/repos/quiet/lib/commits":
			writeJSON(t, w, []map[string]any{})
		case r.URL.Path == "/repos/good/lib/actions/workflows":
			writeJSON(t, w, map[string]any{
				"total_count": 3,
				"workflows": []map[string]any{
					{"id": 1, "name": "ci"},
					{"id": 2, "name": "release"},
				},
			})
		case r.URL.Path == "/repos/quiet/lib/actions/workflows":
			writeJSON(t, w, map[string]any{"total_count": 0, "workflows": []any{}})
		case r.URL.Path == "/repos/good/lib/actions/runs":
			writeJSON(t, w, map[string]any{
				"total_count": 1,
				"workflow_runs": []map[string]any{{
					"id":         1,
					"status":     "completed",
					"conclusion": "success",
					"created_at": "2026-02-02T00:00:00Z",
				}},
			})
		case r.URL.Path == "/repos/quiet/lib/actions/runs":
			writeJSON(t, w, map[string]any{"total_count": 0, "workflow_runs": []any{}})
		case r.URL.Path == "/repos/good/lib/license":
			writeJSON(t, w, map[string]any{
				"license": map[string]any{
					"spdx_id": "MIT",
					"name":    "MIT License",
					"url":     "https://api.github.com/licenses/mit",
				},
			})
		case r.URL.Path == "/repos/quiet/lib/license":
			http.NotFound(w, r)
		case r.URL.Path == "/repos/good/lib/dependency-graph/sbom":
			writeJSON(t, w, map[string]any{
				"sbom": map[string]any{
					"SPDXID":      "SPDXRef-DOCUMENT",
					"spdxVersion": "SPDX-2.3",
					"creationInfo": map[string]any{
						"created": "2026-02-01T00:00:00Z",
					},
					"packages": []map[string]any{
						{"name": "a"},
						{"name": "b"},
					},
				},
			})
		case r.URL.Path == "/repos/quiet/lib/dependency-graph/sbom":
			http.Error(w, "forbidden", http.StatusForbidden)
		case r.URL.Path == "/repos/good/lib/issues" && r.URL.Query().Get("state") == "open":
			writeJSON(t, w, []map[string]any{{
				"number":       3,
				"created_at":   "2026-01-01T00:00:00Z",
				"pull_request": map[string]any{"url": "https://api.github.test/repos/good/lib/pulls/3"},
			}})
		case r.URL.Path == "/repos/good/lib/issues" && r.URL.Query().Get("state") == "closed":
			writeJSON(t, w, []map[string]any{
				{
					"number":       7,
					"created_at":   "2026-01-01T00:00:00Z",
					"closed_at":    "2026-01-05T00:00:00Z",
					"pull_request": map[string]any{"url": "https://api.github.test/repos/good/lib/pulls/7"},
				},
				{
					"number":       8,
					"created_at":   "2026-01-01T00:00:00Z",
					"closed_at":    "2026-01-10T00:00:00Z",
					"pull_request": map[string]any{"url": "https://api.github.test/repos/good/lib/pulls/8"},
				},
			})
		case r.URL.Path == "/repos/quiet/lib/issues":
			writeJSON(t, w, []any{})
		case r.URL.Path == "/repos/good/lib/issues/7/comments":
			writeJSON(t, w, []map[string]any{{
				"id":         10,
				"created_at": "2026-01-02T00:00:00Z",
			}})
		case r.URL.Path == "/repos/good/lib/pulls/7/reviews":
			writeJSON(t, w, []map[string]any{{
				"id":           11,
				"submitted_at": "2026-01-03T00:00:00Z",
			}})
		case r.URL.Path == "/repos/good/lib/issues/8/comments":
			writeJSON(t, w, []any{})
		case r.URL.Path == "/repos/good/lib/pulls/8/reviews":
			writeJSON(t, w, []any{})
		default:
			t.Fatalf("unexpected GitHub API request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
	})

	plugin := newTestPlugin(t, server.URL)
	repo := &github.Repository{
		Name:          github.Ptr("target"),
		DefaultBranch: github.Ptr("main"),
		Owner:         &github.User{Login: github.Ptr("source")},
	}

	deps := plugin.GatherRepositoryDependencies(t.Context(), repo)
	if len(deps) != 4 {
		t.Fatalf("expected 4 dependencies, got %d", len(deps))
	}

	good := findDependency(t, deps, "github.com/good/lib")
	if !good.Repository.Resolved || good.Repository.Owner != "good" || good.Repository.Name != "lib" {
		t.Fatalf("good dependency did not resolve: %#v", good.Repository)
	}
	if good.Health.LatestRelease == nil || good.Health.LatestRelease.Tag != "v1.3.0" {
		t.Fatalf("latest release not collected: %#v", good.Health.LatestRelease)
	}
	if good.Health.LatestCommit == nil || good.Health.LatestCommit.SHA != "abc123" {
		t.Fatalf("latest commit not collected: %#v", good.Health.LatestCommit)
	}
	if good.Health.Workflows == nil || good.Health.Workflows.Count != 3 || good.Health.Workflows.LatestDefaultBranchRun.Conclusion != "success" {
		t.Fatalf("workflow summary not collected: %#v", good.Health.Workflows)
	}
	if good.SupplyChain.License == nil || good.SupplyChain.License.SPDXID != "MIT" {
		t.Fatalf("license not collected: %#v", good.SupplyChain.License)
	}
	if good.SupplyChain.SBOM == nil || !good.SupplyChain.SBOM.Available || good.SupplyChain.SBOM.PackageCount != 2 {
		t.Fatalf("SBOM not collected: %#v", good.SupplyChain.SBOM)
	}
	if good.Health.PullRequests == nil || good.Health.PullRequests.OpenCount != 1 || good.Health.PullRequests.OpenCountCapped || good.Health.PullRequests.RecentClosedCount != 2 || good.Health.PullRequests.RecentClosedCountCapped {
		t.Fatalf("PR stats not collected: %#v", good.Health.PullRequests)
	}
	if good.Health.PullRequests.MedianDaysToClose == nil || *good.Health.PullRequests.MedianDaysToClose != 6.5 {
		t.Fatalf("expected median days to close 6.5, got %#v", good.Health.PullRequests.MedianDaysToClose)
	}
	if good.Health.PullRequests.MedianHoursToFirstInteraction == nil || *good.Health.PullRequests.MedianHoursToFirstInteraction != 24 {
		t.Fatalf("expected median hours to first interaction 24, got %#v", good.Health.PullRequests.MedianHoursToFirstInteraction)
	}
	if good.Health.PullRequests.FirstInteractionSampledPullRequests != 2 {
		t.Fatalf("expected two first-interaction samples, got %d", good.Health.PullRequests.FirstInteractionSampledPullRequests)
	}
	if !good.CollectionStatus.HealthCollected {
		t.Fatal("expected complete health collection to be marked collected")
	}
	goodSubmodule := findDependency(t, deps, "github.com/good/lib/submodule")
	if goodSubmodule.Health.LatestRelease == nil || goodSubmodule.Health.LatestRelease.Tag != "v1.3.0" {
		t.Fatalf("expected cached latest release for submodule dependency, got %#v", goodSubmodule.Health.LatestRelease)
	}
	if goodRepoGetCount != 1 {
		t.Fatalf("expected good/lib repository facts to be fetched once, got %d", goodRepoGetCount)
	}

	quiet := findDependency(t, deps, "github.com/quiet/lib")
	if !quiet.Health.RepositoryArchived {
		t.Fatal("expected quiet dependency to be archived")
	}
	if quiet.Health.LatestRelease != nil {
		t.Fatalf("expected no latest release, got %#v", quiet.Health.LatestRelease)
	}
	if quiet.SupplyChain.License == nil || !quiet.SupplyChain.License.Collected || quiet.SupplyChain.License.SPDXID != "" {
		t.Fatalf("expected unknown collected license, got %#v", quiet.SupplyChain.License)
	}
	if quiet.CollectionStatus.SBOMCollected {
		t.Fatal("expected inaccessible SBOM not to be marked collected")
	}
	if len(quiet.CollectionStatus.Errors) == 0 {
		t.Fatal("expected inaccessible SBOM to record a collection error")
	}
	if !quiet.CollectionStatus.HealthCollected {
		t.Fatal("expected SBOM-only failure not to mark health collection incomplete")
	}

	unresolved := findDependency(t, deps, "example.com/unresolved/lib")
	if unresolved.Repository.Resolved {
		t.Fatalf("expected unresolved dependency, got %#v", unresolved.Repository)
	}
}

func TestGatherRepositoryDependenciesRequiresConfiguration(t *testing.T) {
	plugin := &GithubReposPlugin{}
	repo := &github.Repository{
		Name:          github.Ptr("target"),
		DefaultBranch: github.Ptr("main"),
		Owner:         &github.User{Login: github.Ptr("source")},
	}

	if deps := plugin.GatherRepositoryDependencies(t.Context(), repo); deps != nil {
		t.Fatalf("expected no dependencies from unconfigured plugin, got %#v", deps)
	}

	if _, err := plugin.gatherRepositoryDependencies(t.Context(), repo, nil); err == nil {
		t.Fatal("expected unconfigured plugin to return an error")
	}
}

func TestCollectDependencySBOMTreatsNotFoundAsCollectedUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/missing/lib/dependency-graph/sbom" {
			t.Fatalf("unexpected GitHub API request: %s", r.URL.Path)
		}
		http.NotFound(w, r)
	})

	plugin := newTestPlugin(t, server.URL)
	dep := newRepositoryDependency(goModuleDependency{
		Name:    "github.com/missing/lib",
		Version: "v1.0.0",
		Direct:  true,
	})
	dep.Repository = &DependencyRepository{
		Provider: "github",
		Owner:    "missing",
		Name:     "lib",
		URL:      "https://github.com/missing/lib",
		Resolved: true,
	}

	plugin.collectDependencySBOM(t.Context(), dep)

	if dep.SupplyChain.SBOM == nil || !dep.SupplyChain.SBOM.Collected || dep.SupplyChain.SBOM.Available {
		t.Fatalf("expected unavailable SBOM to be collected without availability, got %#v", dep.SupplyChain.SBOM)
	}
	if !dep.CollectionStatus.SBOMCollected {
		t.Fatal("expected SBOM collection status to be marked collected")
	}
	if len(dep.CollectionStatus.Errors) != 0 {
		t.Fatalf("expected no collection errors for missing SBOM, got %#v", dep.CollectionStatus.Errors)
	}
}

func TestCollectDependencyRepositoryFactsMarksHealthIncompleteOnHealthError(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/good/lib":
			writeJSON(t, w, map[string]any{
				"name":           "lib",
				"full_name":      "good/lib",
				"default_branch": "main",
				"archived":       false,
			})
		case r.URL.Path == "/repos/good/lib/releases/latest":
			http.NotFound(w, r)
		case r.URL.Path == "/repos/good/lib/commits":
			writeJSON(t, w, []map[string]any{{
				"sha": "abc123",
				"commit": map[string]any{
					"committer": map[string]any{"date": "2026-02-01T00:00:00Z"},
				},
			}})
		case r.URL.Path == "/repos/good/lib/actions/workflows":
			http.Error(w, "forbidden", http.StatusForbidden)
		case r.URL.Path == "/repos/good/lib/issues":
			writeJSON(t, w, []any{})
		case r.URL.Path == "/repos/good/lib/license":
			http.NotFound(w, r)
		case r.URL.Path == "/repos/good/lib/dependency-graph/sbom":
			writeJSON(t, w, map[string]any{"sbom": map[string]any{}})
		default:
			t.Fatalf("unexpected GitHub API request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
	})

	plugin := newTestPlugin(t, server.URL)
	dep := newRepositoryDependency(goModuleDependency{Name: "github.com/good/lib", Version: "v1.0.0", Direct: true})
	resolveDependencyRepository(dep)

	plugin.collectDependencyRepositoryFacts(t.Context(), dep)

	if dep.CollectionStatus.HealthCollected {
		t.Fatal("expected health collection to remain incomplete after workflows error")
	}
	if len(dep.CollectionStatus.Errors) != 1 || dep.CollectionStatus.Errors[0].Scope != "workflows" {
		t.Fatalf("expected one workflows collection error, got %#v", dep.CollectionStatus.Errors)
	}
}

func TestGatherRepositoryDependenciesMissingGoMod(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/source/target/contents/go.mod" {
			http.NotFound(w, r)
			return
		}
		t.Fatalf("unexpected GitHub API request: %s", r.URL.Path)
	})

	plugin := newTestPlugin(t, server.URL)
	repo := &github.Repository{
		Name:          github.Ptr("target"),
		DefaultBranch: github.Ptr("main"),
		Owner:         &github.User{Login: github.Ptr("source")},
	}
	deps := plugin.GatherRepositoryDependencies(t.Context(), repo)
	if len(deps) != 0 {
		t.Fatalf("expected no dependencies for missing go.mod, got %d", len(deps))
	}
}

func TestGatherRepositoryDependenciesMissingGoModEmitsCollectionGapForPolicies(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/source/target/contents/go.mod" {
			http.NotFound(w, r)
			return
		}
		t.Fatalf("unexpected GitHub API request: %s", r.URL.Path)
	})

	plugin := newTestPlugin(t, server.URL)
	repo := &github.Repository{
		Name:          github.Ptr("target"),
		DefaultBranch: github.Ptr("main"),
		Owner:         &github.User{Login: github.Ptr("source")},
	}
	emitted := []*RepositoryDependency{}
	deps, err := plugin.gatherRepositoryDependencies(t.Context(), repo, func(dep *RepositoryDependency) error {
		emitted = append(emitted, dep)
		return nil
	})
	if err != nil {
		t.Fatalf("gatherRepositoryDependencies returned error: %v", err)
	}
	if len(deps) != 1 || len(emitted) != 1 {
		t.Fatalf("expected one collection gap dependency, got deps=%d emitted=%d", len(deps), len(emitted))
	}
	dep := emitted[0]
	if dep.Name != "dependency-collection-unavailable" {
		t.Fatalf("expected collection gap dependency name, got %q", dep.Name)
	}
	if dep.CollectionStatus == nil || dep.CollectionStatus.DependencyParsed {
		t.Fatalf("expected dependency parsing to be unavailable, got %#v", dep.CollectionStatus)
	}
	if len(dep.CollectionStatus.Errors) != 1 || dep.CollectionStatus.Errors[0].Scope != "go_mod_fetch" {
		t.Fatalf("expected one go_mod_fetch collection error, got %#v", dep.CollectionStatus.Errors)
	}
	if !strings.Contains(dep.CollectionStatus.Errors[0].Message, "404") {
		t.Fatalf("expected go_mod_fetch collection error to preserve GitHub status, got %q", dep.CollectionStatus.Errors[0].Message)
	}
}

func TestNewDependencyCollectionGapSerializesEmptyErrors(t *testing.T) {
	dep := newDependencyCollectionGap("go_mod_fetch", nil)
	payload, err := json.Marshal(dep)
	if err != nil {
		t.Fatalf("failed to marshal dependency collection gap: %v", err)
	}
	if !strings.Contains(string(payload), `"errors":[]`) {
		t.Fatalf("expected empty errors array, got %s", payload)
	}
}

func TestEvaluatePoliciesRunsDependencyPoliciesPerDependency(t *testing.T) {
	policyDir := filepath.Join(t.TempDir(), "plugin-github-repositories-dependency-policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatalf("failed to create policy dir: %v", err)
	}
	rego := []byte(`package compliance_framework.dependency_archived

title := "Dependency is not archived"
description := "Dependency repositories should not be archived."

violation[{"id": "dependency_repository_archived"}] if {
	object.get(object.get(input.policy_data, "dependency_health", {}), "fail_archived", false)
	input.dependency.health.repository_archived == true
}
`)
	if err := os.WriteFile(filepath.Join(policyDir, "dependency_archived.rego"), rego, 0o644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	plugin := &GithubReposPlugin{
		Logger: hclog.NewNullLogger(),
	}
	repo := &github.Repository{
		Name:     github.Ptr("api"),
		FullName: github.Ptr("ccf/api"),
		HTMLURL:  github.Ptr("https://github.com/ccf/api"),
		Owner:    &github.User{Login: github.Ptr("ccf"), Name: github.Ptr("Continuous Compliance Framework")},
	}
	data := &SaturatedRepository{
		Settings:   repo,
		PolicyData: map[string]interface{}{"dependency_health": map[string]interface{}{"fail_archived": true}},
	}
	deps := []*RepositoryDependency{
		{
			Name:            "internally-maintained-open-source/foo",
			Ecosystem:       "go",
			DeclaredVersion: "v1.0.0",
			Repository:      &DependencyRepository{URL: "https://github.com/internally-maintained-open-source/foo"},
			Health:          &DependencyHealth{RepositoryArchived: false},
		},
		{
			Name:            "competitor-maintained-open-source/bar",
			Ecosystem:       "go",
			DeclaredVersion: "v2.0.0",
			Repository:      &DependencyRepository{URL: "https://github.com/competitor-maintained-open-source/bar"},
			Health:          &DependencyHealth{RepositoryArchived: true},
		},
	}

	evidence, err := plugin.EvaluatePolicies(t.Context(), data, deps, []string{policyDir}, data.PolicyData)
	if err != nil {
		t.Fatalf("EvaluatePolicies returned error: %v", err)
	}
	if len(evidence) != 2 {
		t.Fatalf("expected one evidence per dependency, got %d", len(evidence))
	}

	byDependency := map[string]*proto.Evidence{}
	for _, ev := range evidence {
		labels := ev.GetLabels()
		byDependency[labels["dependency"]] = ev
		if labels["type"] != "repository-dependency" {
			t.Fatalf("expected dependency evidence type label, got %q", labels["type"])
		}
	}

	foo := byDependency["internally-maintained-open-source/foo"]
	if foo == nil {
		t.Fatal("missing evidence for foo dependency")
	}
	if foo.GetStatus().GetState() != proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED {
		t.Fatalf("expected foo evidence to pass, got %s", foo.GetStatus().GetState())
	}
	if len(foo.GetSubjects()) == 0 || !strings.Contains(foo.GetSubjects()[0].GetIdentifier(), "internally-maintained-open-source/foo@v1.0.0") {
		t.Fatalf("expected foo dependency subject, got %#v", foo.GetSubjects())
	}
	if !evidenceHasHref(foo, "https://github.com/internally-maintained-open-source/foo") {
		t.Fatalf("expected foo evidence to link to dependency repository, got %#v", foo.GetLinks())
	}

	bar := byDependency["competitor-maintained-open-source/bar"]
	if bar == nil {
		t.Fatal("missing evidence for bar dependency")
	}
	if bar.GetStatus().GetState() != proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED {
		t.Fatalf("expected bar evidence to fail, got %s", bar.GetStatus().GetState())
	}
	if len(bar.GetProps()) != 1 || bar.GetProps()[0].GetValue() != "dependency_repository_archived" {
		t.Fatalf("expected archived violation prop, got %#v", bar.GetProps())
	}
	if !evidenceHasHref(bar, "https://github.com/competitor-maintained-open-source/bar") {
		t.Fatalf("expected bar evidence to link to dependency repository, got %#v", bar.GetLinks())
	}
}

func evidenceHasHref(evidence *proto.Evidence, href string) bool {
	for _, link := range evidence.GetLinks() {
		if link.GetHref() == href {
			return true
		}
	}
	return false
}

func TestDependencyPolicyInputDefaultsPolicyData(t *testing.T) {
	repo := &github.Repository{
		Name:     github.Ptr("api"),
		FullName: github.Ptr("ccf/api"),
		HTMLURL:  github.Ptr("https://github.com/ccf/api"),
		Owner:    &github.User{Login: github.Ptr("ccf")},
	}
	input := dependencyPolicyInput(repo, &RepositoryDependency{Name: "github.com/example/lib"}, nil)
	if input.PolicyData == nil {
		t.Fatal("expected dependency policy data to default to an empty map")
	}
	if len(input.PolicyData) != 0 {
		t.Fatalf("expected empty dependency policy data, got %#v", input.PolicyData)
	}
}

func TestMedianHoursToFirstInteractionStopsAfterFirstCollectionError(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	requests := 0
	mux.HandleFunc("/repos/good/lib/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "forbidden", http.StatusForbidden)
	})

	plugin := newTestPlugin(t, server.URL)
	dep := newRepositoryDependency(goModuleDependency{Name: "github.com/good/lib", Version: "v1.0.0", Direct: true})
	resolveDependencyRepository(dep)
	dep.Health.PullRequests = &DependencyPullRequestStats{}
	prs := []*github.Issue{
		{Number: github.Ptr(1), CreatedAt: githubTimestamp("2026-01-01T00:00:00Z")},
		{Number: github.Ptr(2), CreatedAt: githubTimestamp("2026-01-02T00:00:00Z")},
	}

	median := plugin.medianHoursToFirstInteraction(t.Context(), dep, prs)

	if median != nil {
		t.Fatalf("expected no median after collection error, got %v", *median)
	}
	if requests != 1 {
		t.Fatalf("expected first interaction collection to stop after one error, got %d requests", requests)
	}
	if len(dep.CollectionStatus.Errors) != 1 || dep.CollectionStatus.Errors[0].Scope != "pull_request_interactions" {
		t.Fatalf("expected one pull_request_interactions error, got %#v", dep.CollectionStatus.Errors)
	}
}

func TestMedianHoursToFirstInteractionSamplesOnlyPullRequestsWithCreatedAt(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	requests := 0
	mux.HandleFunc("/repos/good/lib/issues/2/comments", func(w http.ResponseWriter, r *http.Request) {
		requests++
		writeJSON(t, w, []map[string]any{{
			"created_at": "2026-01-03T00:00:00Z",
		}})
	})
	mux.HandleFunc("/repos/good/lib/pulls/2/reviews", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, []map[string]any{})
	})

	plugin := newTestPlugin(t, server.URL)
	dep := newRepositoryDependency(goModuleDependency{Name: "github.com/good/lib", Version: "v1.0.0", Direct: true})
	resolveDependencyRepository(dep)
	dep.Health.PullRequests = &DependencyPullRequestStats{}
	prs := []*github.Issue{
		{Number: github.Ptr(1)},
		{Number: github.Ptr(2), CreatedAt: githubTimestamp("2026-01-02T00:00:00Z")},
	}

	median := plugin.medianHoursToFirstInteraction(t.Context(), dep, prs)

	if median == nil || *median != 24 {
		t.Fatalf("expected median first interaction to use valid PR, got %#v", median)
	}
	if requests != 1 {
		t.Fatalf("expected one first interaction request, got %d", requests)
	}
	if dep.Health.PullRequests.FirstInteractionSampledPullRequests != 1 {
		t.Fatalf("expected one sampled pull request, got %d", dep.Health.PullRequests.FirstInteractionSampledPullRequests)
	}
}

func TestListPullRequestIssuesFiltersPullRequests(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/repos/good/lib/issues", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != "closed" {
			t.Fatalf("unexpected state: %s", r.URL.Query().Get("state"))
		}
		writeJSON(t, w, []map[string]any{
			{"number": 1, "pull_request": map[string]any{"url": "https://api.github.test/repos/good/lib/pulls/1"}},
			{"number": 2},
		})
	})

	plugin := newTestPlugin(t, server.URL)
	prs, capped, err := plugin.listPullRequestIssues(t.Context(), "good", "lib", "closed", time.Time{})
	if err != nil {
		t.Fatalf("listPullRequestIssues returned error: %v", err)
	}
	if capped {
		t.Fatal("expected uncapped pull request issue result")
	}
	if len(prs) != 1 {
		t.Fatalf("expected 1 pull request issue, got %d", len(prs))
	}
	if prs[0].GetNumber() != 1 {
		t.Fatalf("unexpected pull request issue number: %d", prs[0].GetNumber())
	}
}

func TestListPullRequestIssuesSortsOpenPullRequestsOldestFirst(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/repos/good/lib/issues", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != "open" {
			t.Fatalf("unexpected state: %s", r.URL.Query().Get("state"))
		}
		if r.URL.Query().Get("sort") != "created" {
			t.Fatalf("unexpected sort: %s", r.URL.Query().Get("sort"))
		}
		if r.URL.Query().Get("direction") != "asc" {
			t.Fatalf("unexpected direction: %s", r.URL.Query().Get("direction"))
		}
		writeJSON(t, w, []map[string]any{{
			"number":       1,
			"pull_request": map[string]any{"url": "https://api.github.test/repos/good/lib/pulls/1"},
		}})
	})

	plugin := newTestPlugin(t, server.URL)
	prs, capped, err := plugin.listPullRequestIssues(t.Context(), "good", "lib", "open", time.Time{})
	if err != nil {
		t.Fatalf("listPullRequestIssues returned error: %v", err)
	}
	if capped {
		t.Fatal("expected uncapped pull request issue result")
	}
	if len(prs) != 1 {
		t.Fatalf("expected 1 pull request issue, got %d", len(prs))
	}
}

func TestListPullRequestIssuesStopsAtMaxPages(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	requests := 0
	mux.HandleFunc("/repos/good/lib/issues", func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests > dependencyPRMaxPages {
			t.Fatalf("requested more than %d pages", dependencyPRMaxPages)
		}
		nextPage := requests + 1
		w.Header().Set("Link", fmt.Sprintf(`<%s/repos/good/lib/issues?page=%d>; rel="next"`, server.URL, nextPage))
		writeJSON(t, w, []map[string]any{{
			"number":       requests,
			"pull_request": map[string]any{"url": fmt.Sprintf("https://api.github.test/repos/good/lib/pulls/%d", requests)},
		}})
	})

	plugin := newTestPlugin(t, server.URL)
	prs, capped, err := plugin.listPullRequestIssues(t.Context(), "good", "lib", "closed", time.Time{})
	if err != nil {
		t.Fatalf("listPullRequestIssues returned error: %v", err)
	}
	if !capped {
		t.Fatal("expected capped pull request issue result")
	}
	if requests != dependencyPRMaxPages {
		t.Fatalf("expected %d requests, got %d", dependencyPRMaxPages, requests)
	}
	if len(prs) != dependencyPRMaxPages {
		t.Fatalf("expected %d pull requests, got %d", dependencyPRMaxPages, len(prs))
	}
}

func TestFilterPullRequestsClosedSinceUsesClosedAt(t *testing.T) {
	since := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	prs := []*github.Issue{
		{
			Number:   github.Ptr(1),
			ClosedAt: githubTimestamp("2026-01-09T23:59:59Z"),
		},
		{
			Number:   github.Ptr(2),
			ClosedAt: githubTimestamp("2026-01-10T00:00:00Z"),
		},
		{
			Number: github.Ptr(3),
		},
	}

	filtered := filterPullRequestsClosedSince(prs, since)
	if len(filtered) != 1 || filtered[0].GetNumber() != 2 {
		t.Fatalf("expected only PR 2, got %#v", filtered)
	}
}

func assertStringSlicesEqual(t *testing.T, got []string, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func newTestPlugin(t *testing.T, serverURL string) *GithubReposPlugin {
	t.Helper()
	client := github.NewClient(http.DefaultClient)
	baseURL, err := url.Parse(serverURL + "/")
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	client.BaseURL = baseURL
	return &GithubReposPlugin{
		Logger:       hclog.NewNullLogger(),
		githubClient: client,
		config: &PluginConfig{
			dependencyHealthEnabled:                 true,
			dependencyHealthMaxDependencies:         50,
			dependencyHealthClosedPRLookbackDays:    3650,
			dependencyHealthIncludeUnresolved:       true,
			dependencyHealthCollectSBOM:             true,
			dependencyHealthPRInteractionSampleSize: 20,
		},
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}
}

func findDependency(t *testing.T, deps []*RepositoryDependency, name string) *RepositoryDependency {
	t.Helper()
	for _, dep := range deps {
		if dep.Name == name {
			return dep
		}
	}
	t.Fatalf("dependency %q not found; got %s", name, dependencyNames(deps))
	return nil
}

func dependencyNames(deps []*RepositoryDependency) string {
	names := make([]string, 0, len(deps))
	for _, dep := range deps {
		names = append(names, dep.Name)
	}
	return strings.Join(names, ", ")
}

func githubTimestamp(value string) *github.Timestamp {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return &github.Timestamp{Time: parsed}
}
