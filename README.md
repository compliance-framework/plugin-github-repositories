# Compliance Framework - Github Repoistory Plugin

Fetches information regarding the repository, including

- Administration information
- Rulesets
- Jobs
- Releases
- SBOM information

This plugin is intended to be run as part of an aggregate agent, and will execute the policy suite for each repository.

## Authentication

To authenticate this plugin, you must provide a token which has at minimum the following permissions:

- Actions (read-only) - Used to pull workflow jobs and success
- Administration (read-only) - Used to check configuration and rulesets for a repository
- Metadata (read-only) - Required by github
- Pull Requests (read-oly) - Used to pull PRs and status
- Secret scaning alerts (read-only) - Used to heck if secrets have found
- Secret scanning push protection bypass requests (read-only) - Used to check the process of any bypass requests

## Configration

```yaml
plugins:
  github_repos:
    token: "gh-pat-abc123"
    # Organization which you want to check the repos of
    organization: octocat
    # The following items are mutually exclusive, so cannot be set together. If neither are set, all repos are
    # pulled and tested, otherwise the selection is chosen below
    # Alternatively, these can be limited via the PAT configuration
    included_repos: foo,bar,baz
    excluded_repos: quix,quiz
```

## Integration testing

This plugin contains unit tests as well as integration tests.

The Integration tests need a GitHub token to call to the GitHub API.

```shell
GITHUB_TOKEN="<TOKEN>" go test ./... -v --tags integration
```

## Policies

When writing OPA / Rego policies for this plugin, they must be added under the `compliance_framework` rego package:

```rego
# deny_critical_severity.rego
# package compliance_framework.[YOUR_RULE_PATH]
package compliance_framework.deny_critical_severity
```

## Releases

This plugin is released using goreleaser to build binaries, and GOOCI to upload artifacts to OCI,
which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub releases page.

You can find the OCI implementations in the GitHub Packages page.
