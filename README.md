# Compliance Framework - GitHub Repository Plugin

Fetches information regarding the repository, including

- Repository metadata and settings
- Configured workflows
- Recent workflow runs
- Optional direct Go dependency health and supply-chain visibility facts

This plugin is intended to be run as part of an aggregate agent, and will execute the policy suite for each repository.

## Authentication

To authenticate this plugin, you must provide a token which has at minimum the following permissions:

- Actions (read-only) - Used to pull workflow jobs and success
- Administration (read-only) - Used to check configuration and rulesets for a repository
- Contents (read-only) - Used to read repository files such as `go.mod` when dependency health collection is enabled
- Metadata (read-only) - Required by GitHub
- Pull Requests (read-only) - Used to pull PRs and status
- Secret scanning alerts (read-only) - Used to check if secrets have been found
- Secret scanning push protection bypass requests (read-only) - Used to check the process of any bypass requests

When dependency health collection is enabled, the token also uses repository contents, Actions, pull requests, license, and dependency graph/SBOM APIs against resolved public GitHub dependency repositories. Missing permissions or unavailable upstream data for resolved dependency repositories are recorded as dependency-level collection gaps and do not fail the repository evaluation.

## Configuration

```yaml
plugins:
  github_repos:
    token: "gh-pat-abc123"
    # Organization which you want to check the repos of
    organization: octocat
    # The following items are mutually exclusive, so cannot be set together. If neither are set, all repos are
    # pulled and tested, otherwise the selection is chosen below
    # Alternatively, these can be limited via the PAT configuration
    included_repositories: foo,bar,baz
    excluded_repositories: quix,quiz
    # Optional dependency health collection. Disabled by default to avoid extra GitHub API usage.
    dependency_health_enabled: "false"
    dependency_health_max_dependencies: "50"
    dependency_health_closed_pr_lookback_days: "180"
    dependency_health_include_unresolved: "true"
    dependency_health_collect_sbom: "true"
    dependency_health_pr_interaction_sample_size: "20"
```

Dependency health collection currently parses direct `go.mod` dependencies only. It resolves module paths that start with `github.com/{owner}/{repo}` and collects public upstream repository health signals.
Dependency policies are now evaluated using policy behavior metadata from the request (`dependency` behavior), and dependency inputs expose repository/dependency context under `input.dependency` and `input.repository` with request policy data available at `input.policy_data`. This can add several GitHub API calls per direct dependency, so enable it only for policy collections that need dependency evidence.

Policy input migration: use request `policy_data` for new policy-specific inputs. The legacy plugin config key `policy_input` is still accepted as a JSON string fallback when request `policy_data` is not provided, and repository policy evaluation exposes the same data under both `input.policy_data` and the legacy `input.policy_input` key for compatibility. If both `policy_data` and `policy_input` are provided, `policy_data` is used.

## Integration testing

This plugin contains unit tests as well as integration tests.

The integration tests need a GitHub token to call the GitHub API.

```shell
GITHUB_TOKEN="<TOKEN>" go test ./... -v --tags integration
```

## Policies

When writing OPA/Rego policies for this plugin, they must be added under the `compliance_framework` Rego package:

```rego
# deny_critical_severity.rego
# package compliance_framework.[YOUR_RULE_PATH]
package compliance_framework.deny_critical_severity
```

## Releases

This plugin is released using GoReleaser to build binaries, and GOOCI to upload artifacts to OCI,
which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub Releases page.

You can find the OCI implementations in the GitHub Packages page.
