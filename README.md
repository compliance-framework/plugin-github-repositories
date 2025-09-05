# Compliance Framework - GitHub Repository Plugin

Fetches information regarding the repository, including

- Repository metadata and settings
- Configured workflows
- Recent workflow runs

This plugin is intended to be run as part of an aggregate agent, and will execute the policy suite for each repository.

## Authentication

To authenticate this plugin, you must provide a token which has at minimum the following permissions:

- Actions (read-only) - Used to pull workflow jobs and success
- Administration (read-only) - Used to check configuration and rulesets for a repository
- Metadata (read-only) - Required by GitHub
- Pull Requests (read-only) - Used to pull PRs and status
- Secret scanning alerts (read-only) - Used to check if secrets have been found
- Secret scanning push protection bypass requests (read-only) - Used to check the process of any bypass requests

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
```

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
